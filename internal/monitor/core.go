package monitor

import (
	"cmp"
	"slices"
	"sync"
	"time"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
	"github.com/Daviey/barmkin/internal/telemetry"
)

// Limits on in-memory state. A request that would pass one is answered
// unavailable, which every client treats as a deny.
const (
	MaxSessions      = 1 << 16 // registered sessions
	MaxPreregistered = 4096    // live pre-registrations
)

// DefaultPreregisterTTL is how long a pre-registration stays live. The shim
// pre-registers a call moments before the managed gate asks about it.
const DefaultPreregisterTTL = 10 * time.Second

// sessionKey names a session. The client's uid is part of every key, so one
// user's sessions are invisible to every other user.
type sessionKey struct {
	uid     uint32
	host    proto.Host
	session string
}

// lineageKey names a root lineage: a top-level session and every session
// registered under it. Legs belong to lineages.
type lineageKey struct {
	uid  uint32
	host proto.Host
	root string
}

type callKey struct {
	sessionKey
	call string
}

// appender is the journal as the core uses it.
type appender interface {
	Append(...journal.Record) error
}

// core holds the monitor's state and answers its operations. One mutex
// serialises every operation; a change is journaled under it before the
// operation returns, and only then handed to the telemetry export, which
// never blocks.
type core struct {
	mu       sync.Mutex
	journal  appender
	sessions map[sessionKey]string // session -> the root of its lineage
	lineages map[lineageKey]*proto.Legs
	calls    map[callKey]time.Time // pre-registrations and their expiry
	ttl      time.Duration
	now      func() time.Time
	degraded bool // a change could not be journaled, or the core is closed

	telemetry *telemetry.Exporter // nil when export is off

	// restarted holds the monitor_restart raises newCore added, for the
	// start's telemetry once the snapshot holding them is durable.
	restarted []journal.Record
}

// newCore rebuilds state from replayed records. When the journal did not
// end in a clean stop, a request the last run accepted may have been lost,
// so every lineage's untrusted leg is raised by monitor_restart.
func newCore(records []journal.Record, clean bool) *core {
	c := &core{
		sessions: map[sessionKey]string{},
		lineages: map[lineageKey]*proto.Legs{},
		calls:    map[callKey]time.Time{},
		ttl:      DefaultPreregisterTTL,
		now:      time.Now,
	}
	for _, r := range records {
		switch r.Kind {
		case journal.KindRegister:
			sk := sessionKey{r.UID, r.Host, r.Session}
			if _, ok := c.sessions[sk]; !ok {
				c.sessions[sk] = r.Root
			}
			c.lineage(lineageKey{r.UID, r.Host, r.Root})
		case journal.KindRaise:
			c.raise(lineageKey{r.UID, r.Host, r.Root}, r.Leg, r.Source)
		}
	}
	if !clean {
		for lk := range c.lineages {
			c.restarted = append(c.restarted, c.raise(lk, journal.LegUntrusted, proto.SourceMonitorRestart)...)
		}
	}
	return c
}

// lineage returns lk's legs, creating clean legs when lk is new.
func (c *core) lineage(lk lineageKey) *proto.Legs {
	legs, ok := c.lineages[lk]
	if !ok {
		legs = &proto.Legs{Untrusted: proto.SourceNone, Sensitive: proto.SourceNone}
		c.lineages[lk] = legs
	}
	return legs
}

// raise raises leg of lk to source, unless it is already up: legs only
// rise, and the first source to raise one stays. It returns the record to
// journal, or none when nothing changed.
func (c *core) raise(lk lineageKey, leg journal.Leg, source proto.Source) []journal.Record {
	legs := c.lineage(lk)
	slot := &legs.Untrusted
	if leg == journal.LegSensitive {
		slot = &legs.Sensitive
	}
	if *slot != proto.SourceNone {
		return nil
	}
	*slot = source
	return []journal.Record{{Kind: journal.KindRaise, UID: lk.uid, Host: lk.host, Root: lk.root, Leg: leg, Source: source}}
}

// commit journals records before the operation that made them answers.
// Memory already holds the change, which only ever tightens; if the journal
// fails, the core degrades and denies everything from then on. Telemetry
// sees a change only after its append returned.
func (c *core) commit(records []journal.Record) error {
	if len(records) == 0 {
		return nil
	}
	if err := c.journal.Append(records...); err != nil {
		c.degraded = true
		c.telemetry.Degraded(c.now())
		return fail(proto.CodeUnavailable)
	}
	c.telemetry.Journaled(c.now(), records...)
	return nil
}

// snapshot returns records that rebuild the current state, in a stable
// order: every session, then every raised leg.
func (c *core) snapshot() []journal.Record {
	var regs, raises []journal.Record
	for sk, root := range c.sessions {
		regs = append(regs, journal.Record{Kind: journal.KindRegister, UID: sk.uid, Host: sk.host, Session: sk.session, Root: root})
	}
	for lk, legs := range c.lineages {
		if legs.Untrusted != proto.SourceNone {
			raises = append(raises, journal.Record{Kind: journal.KindRaise, UID: lk.uid, Host: lk.host, Root: lk.root, Leg: journal.LegUntrusted, Source: legs.Untrusted})
		}
		if legs.Sensitive != proto.SourceNone {
			raises = append(raises, journal.Record{Kind: journal.KindRaise, UID: lk.uid, Host: lk.host, Root: lk.root, Leg: journal.LegSensitive, Source: legs.Sensitive})
		}
	}
	order := func(a, b journal.Record) int {
		return cmp.Or(cmp.Compare(a.UID, b.UID), cmp.Compare(a.Host, b.Host),
			cmp.Compare(a.Root, b.Root), cmp.Compare(a.Session, b.Session), cmp.Compare(a.Leg, b.Leg))
	}
	slices.SortFunc(regs, order)
	slices.SortFunc(raises, order)
	return append(regs, raises...)
}

// close stops the core answering and journals a clean stop.
func (c *core) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.degraded {
		return nil
	}
	c.degraded = true
	stop := journal.Record{Kind: journal.KindShutdown}
	if err := c.journal.Append(stop); err != nil {
		return err
	}
	c.telemetry.Journaled(c.now(), stop)
	return nil
}

func fail(code proto.Code) error { return &proto.Error{Code: code} }

// postureOK is the posture gate: the host must run tools in its sandbox,
// and that sandbox must not open every Unix socket, which would let a
// sandboxed tool reach this monitor.
func postureOK(p proto.Posture) bool { return p.SandboxEnabled && !p.AllowAllUnixSockets }

// root resolves the lineage a token names: a registered session's own
// lineage root, or the token itself.
func (c *core) root(uid uint32, host proto.Host, token string) string {
	if root, ok := c.sessions[sessionKey{uid, host, token}]; ok {
		return root
	}
	return token
}

// known returns the legs of a registered session, or fails unknown_session.
func (c *core) known(uid uint32, host proto.Host, session string) (lineageKey, *proto.Legs, error) {
	if c.degraded {
		return lineageKey{}, nil, fail(proto.CodeUnavailable)
	}
	root, ok := c.sessions[sessionKey{uid, host, session}]
	if !ok {
		return lineageKey{}, nil, fail(proto.CodeUnknownSession)
	}
	lk := lineageKey{uid, host, root}
	return lk, c.lineage(lk), nil
}

// handle answers one decoded request from a client with uid.
func (c *core) handle(uid uint32, req proto.Message) (proto.Message, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch req := req.(type) {
	case *proto.RegisterRequest:
		return c.register(uid, req)
	case *proto.PreregisterRequest:
		return c.preregister(uid, req)
	case *proto.GateRequest:
		return c.gate(uid, req)
	case *proto.DecideRequest:
		_, legs, err := c.known(uid, req.Host, req.Session)
		if err != nil {
			return nil, err
		}
		resp := decide(req.Classes, *legs)
		return &resp, nil
	case *proto.ScreenRequest:
		return c.screen(uid, req)
	case *proto.ObserveRequest:
		return c.observe(uid, req)
	case *proto.StatusRequest:
		_, legs, err := c.known(uid, req.Host, req.Session)
		if err != nil {
			return nil, err
		}
		// The monitor core has no classifier, so only local scores apply.
		return &proto.StatusResponse{Version: proto.Version, Legs: *legs, Classifier: proto.ClassifierDegraded}, nil
	case *proto.HealthRequest:
		state := proto.HealthOK
		if c.degraded {
			state = proto.HealthDegraded
		}
		return &proto.HealthResponse{Version: proto.Version, State: state}, nil
	}
	return nil, fail(proto.CodeBadRequest)
}

// register opens or resumes a session. An insecure posture is refused. A
// new session joins its root's lineage; a lineage the monitor has never
// seen starts clean only for a fresh top-level session, and otherwise with
// its untrusted leg raised by unknown_session, since its history is not
// known to be clean. Registering again returns the legs unchanged, and can
// never move a session to another lineage.
func (c *core) register(uid uint32, req *proto.RegisterRequest) (proto.Message, error) {
	if c.degraded {
		return nil, fail(proto.CodeUnavailable)
	}
	if !postureOK(req.Posture) {
		return nil, fail(proto.CodePostureRefused)
	}
	sk := sessionKey{uid, req.Host, req.Session}
	root := c.root(uid, req.Host, req.Root)
	if have, ok := c.sessions[sk]; ok {
		if root != have && req.Root != have {
			return nil, fail(proto.CodeBadRequest)
		}
		return &proto.RegisterResponse{Version: proto.Version, Legs: *c.lineage(lineageKey{uid, req.Host, have})}, nil
	}
	if len(c.sessions) >= MaxSessions {
		return nil, fail(proto.CodeUnavailable)
	}

	lk := lineageKey{uid, req.Host, root}
	_, seen := c.lineages[lk]
	c.sessions[sk] = root
	legs := c.lineage(lk)
	records := []journal.Record{{Kind: journal.KindRegister, UID: uid, Host: req.Host, Session: req.Session, Root: root}}
	if !seen && !(req.Fresh && root == req.Session) {
		records = append(records, c.raise(lk, journal.LegUntrusted, proto.SourceUnknownSession)...)
	}
	if err := c.commit(records); err != nil {
		return nil, err
	}
	return &proto.RegisterResponse{Version: proto.Version, Legs: *legs}, nil
}

func (c *core) preregister(uid uint32, req *proto.PreregisterRequest) (proto.Message, error) {
	if _, _, err := c.known(uid, req.Host, req.Session); err != nil {
		return nil, err
	}
	now := c.now()
	if len(c.calls) >= MaxPreregistered {
		for k, expiry := range c.calls {
			if !now.Before(expiry) {
				delete(c.calls, k)
			}
		}
	}
	if len(c.calls) >= MaxPreregistered {
		return nil, fail(proto.CodeUnavailable)
	}
	c.calls[callKey{sessionKey{uid, req.Host, req.Session}, req.Call}] = now.Add(c.ttl)
	return &proto.PreregisterResponse{Version: proto.Version, TTLMS: int(c.ttl.Milliseconds())}, nil
}

// gate reports whether a call was pre-registered and is still live. A true
// answer consumes the pre-registration, so it admits one call.
func (c *core) gate(uid uint32, req *proto.GateRequest) (proto.Message, error) {
	if _, _, err := c.known(uid, req.Host, req.Session); err != nil {
		return nil, err
	}
	key := callKey{sessionKey{uid, req.Host, req.Session}, req.Call}
	expiry, ok := c.calls[key]
	delete(c.calls, key)
	live := ok && c.now().Before(expiry)
	return &proto.GateResponse{Version: proto.Version, Preregistered: live}, nil
}

func (c *core) observe(uid uint32, req *proto.ObserveRequest) (proto.Message, error) {
	lk, legs, err := c.known(uid, req.Host, req.Session)
	if err != nil {
		return nil, err
	}
	leg := journal.LegUntrusted
	if req.Source == proto.SourceCredential {
		leg = journal.LegSensitive
	}
	if err := c.commit(c.raise(lk, leg, req.Source)); err != nil {
		return nil, err
	}
	return &proto.ObserveResponse{Version: proto.Version, Legs: *legs}, nil
}

// screen has no classifier in the monitor core. Content sent to screen came
// from an untrusted source, so it raises the untrusted leg for that source,
// and then answers unavailable, which the shim treats as a deny. The
// windows are never read, kept or echoed.
func (c *core) screen(uid uint32, req *proto.ScreenRequest) (proto.Message, error) {
	lk, _, err := c.known(uid, req.Host, req.Session)
	if err != nil {
		return nil, err
	}
	if err := c.commit(c.raise(lk, journal.LegUntrusted, req.Source)); err != nil {
		return nil, err
	}
	return nil, fail(proto.CodeUnavailable)
}
