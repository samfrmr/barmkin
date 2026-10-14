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

// session is a registered session: the root of its lineage, the lineage
// epoch it last registered in, and when, in Unix seconds.
type session struct {
	root  string
	epoch uint64
	at    int64
}

// lineage is a root lineage's taint: its legs, when each rose (Unix
// seconds; 0 while down or when an older journal did not say), its epoch,
// and its history: the raises each earlier epoch held and the clear that
// ended it, in order. Only an administrative clear starts a new epoch.
type lineage struct {
	legs        proto.Legs
	untrustedAt int64
	sensitiveAt int64
	epoch       uint64
	history     []journal.Record
}

// core holds the monitor's state and answers its operations. One mutex
// serialises every operation; a change is journaled under it before the
// operation returns, and only then handed to the telemetry export, which
// never blocks.
type core struct {
	mu       sync.Mutex
	journal  appender
	sessions map[sessionKey]session
	lineages map[lineageKey]*lineage
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
		sessions: map[sessionKey]session{},
		lineages: map[lineageKey]*lineage{},
		calls:    map[callKey]time.Time{},
		ttl:      DefaultPreregisterTTL,
		now:      time.Now,
	}
	for _, r := range records {
		lk := lineageKey{r.UID, r.Host, r.Root}
		switch r.Kind {
		case journal.KindRegister:
			sk := sessionKey{r.UID, r.Host, r.Session}
			s, ok := c.sessions[sk]
			if !ok {
				s.root = r.Root
			}
			s.epoch, s.at = r.Epoch, r.At
			c.sessions[sk] = s
			c.lineage(lk)
		case journal.KindRaise:
			c.raise(lk, r.Leg, r.Source, r.At)
		case journal.KindClear:
			c.applyClear(lk, r)
		}
	}
	if !clean {
		at := c.now().Unix()
		for lk := range c.lineages {
			c.restarted = append(c.restarted, c.raise(lk, journal.LegUntrusted, proto.SourceMonitorRestart, at)...)
		}
	}
	return c
}

var cleanLegs = proto.Legs{Untrusted: proto.SourceNone, Sensitive: proto.SourceNone}

// lineage returns lk's state, creating a clean lineage when lk is new.
func (c *core) lineage(lk lineageKey) *lineage {
	l, ok := c.lineages[lk]
	if !ok {
		l = &lineage{legs: cleanLegs}
		c.lineages[lk] = l
	}
	return l
}

// raise raises leg of lk to source at time at, unless it is already up:
// legs only rise, and the first source to raise one stays. It returns the
// record to journal, or none when nothing changed.
func (c *core) raise(lk lineageKey, leg journal.Leg, source proto.Source, at int64) []journal.Record {
	l := c.lineage(lk)
	slot, when := &l.legs.Untrusted, &l.untrustedAt
	if leg == journal.LegSensitive {
		slot, when = &l.legs.Sensitive, &l.sensitiveAt
	}
	if *slot != proto.SourceNone {
		return nil
	}
	*slot, *when = source, at
	return []journal.Record{raiseRecord(lk, leg, source, at)}
}

func raiseRecord(lk lineageKey, leg journal.Leg, source proto.Source, at int64) journal.Record {
	return journal.Record{Kind: journal.KindRaise, UID: lk.uid, Host: lk.host, Root: lk.root, Leg: leg, Source: source, At: at}
}

// raised returns the raise records that rebuild lk's current legs.
func (l *lineage) raised(lk lineageKey) []journal.Record {
	var out []journal.Record
	if l.legs.Untrusted != proto.SourceNone {
		out = append(out, raiseRecord(lk, journal.LegUntrusted, l.legs.Untrusted, l.untrustedAt))
	}
	if l.legs.Sensitive != proto.SourceNone {
		out = append(out, raiseRecord(lk, journal.LegSensitive, l.legs.Sensitive, l.sensitiveAt))
	}
	return out
}

// applyClear applies a journaled clear record to lk: the raised legs and the
// clear move to the lineage's history, both legs fall, the lineage enters
// the record's epoch, and every pre-registration of its sessions is
// dropped. A session of the lineage registered in an earlier epoch must
// register again before anything else it asks is answered.
func (c *core) applyClear(lk lineageKey, rec journal.Record) {
	l := c.lineage(lk)
	l.history = append(append(l.history, l.raised(lk)...), rec)
	l.legs, l.untrustedAt, l.sensitiveAt = cleanLegs, 0, 0
	l.epoch = rec.Epoch
	for ck := range c.calls {
		if s, ok := c.sessions[ck.sessionKey]; ok && ck.uid == lk.uid && ck.host == lk.host && s.root == lk.root {
			delete(c.calls, ck)
		}
	}
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
// order: every session, then each lineage's history of cleared raises and
// clears, then every raised leg.
func (c *core) snapshot() []journal.Record {
	var regs, history, raises []journal.Record
	for sk, s := range c.sessions {
		regs = append(regs, journal.Record{Kind: journal.KindRegister, UID: sk.uid, Host: sk.host, Session: sk.session, Root: s.root, Epoch: s.epoch, At: s.at})
	}
	for _, lk := range c.lineageKeys() {
		l := c.lineages[lk]
		history = append(history, l.history...)
		raises = append(raises, l.raised(lk)...)
	}
	slices.SortFunc(regs, func(a, b journal.Record) int {
		return cmp.Or(cmp.Compare(a.UID, b.UID), cmp.Compare(a.Host, b.Host),
			cmp.Compare(a.Root, b.Root), cmp.Compare(a.Session, b.Session))
	})
	return append(append(regs, history...), raises...)
}

// lineageKeys returns every lineage's key, sorted.
func (c *core) lineageKeys() []lineageKey {
	keys := make([]lineageKey, 0, len(c.lineages))
	for lk := range c.lineages {
		keys = append(keys, lk)
	}
	slices.SortFunc(keys, func(a, b lineageKey) int {
		return cmp.Or(cmp.Compare(a.uid, b.uid), cmp.Compare(a.host, b.host), cmp.Compare(a.root, b.root))
	})
	return keys
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
	if s, ok := c.sessions[sessionKey{uid, host, token}]; ok {
		return s.root
	}
	return token
}

// known returns the legs of a registered session, or fails
// unknown_session. A session registered before its lineage was cleared is
// unknown until it registers again in the lineage's new epoch.
func (c *core) known(uid uint32, host proto.Host, session string) (lineageKey, *proto.Legs, error) {
	if c.degraded {
		return lineageKey{}, nil, fail(proto.CodeUnavailable)
	}
	s, ok := c.sessions[sessionKey{uid, host, session}]
	if !ok {
		return lineageKey{}, nil, fail(proto.CodeUnknownSession)
	}
	lk := lineageKey{uid, host, s.root}
	l := c.lineage(lk)
	if s.epoch != l.epoch {
		return lineageKey{}, nil, fail(proto.CodeUnknownSession)
	}
	return lk, &l.legs, nil
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
// never move a session to another lineage; a session registered before its
// lineage was cleared joins the lineage's new epoch.
func (c *core) register(uid uint32, req *proto.RegisterRequest) (proto.Message, error) {
	if c.degraded {
		return nil, fail(proto.CodeUnavailable)
	}
	if !postureOK(req.Posture) {
		return nil, fail(proto.CodePostureRefused)
	}
	sk := sessionKey{uid, req.Host, req.Session}
	root := c.root(uid, req.Host, req.Root)
	at := c.now().Unix()
	if have, ok := c.sessions[sk]; ok {
		if root != have.root && req.Root != have.root {
			return nil, fail(proto.CodeBadRequest)
		}
		l := c.lineage(lineageKey{uid, req.Host, have.root})
		if have.epoch != l.epoch {
			rec := journal.Record{Kind: journal.KindRegister, UID: uid, Host: req.Host, Session: req.Session, Root: have.root, Epoch: l.epoch, At: at}
			if err := c.commit([]journal.Record{rec}); err != nil {
				return nil, err
			}
			c.sessions[sk] = session{root: have.root, epoch: l.epoch, at: at}
		}
		return &proto.RegisterResponse{Version: proto.Version, Legs: l.legs}, nil
	}
	if len(c.sessions) >= MaxSessions {
		return nil, fail(proto.CodeUnavailable)
	}

	lk := lineageKey{uid, req.Host, root}
	_, seen := c.lineages[lk]
	l := c.lineage(lk)
	c.sessions[sk] = session{root: root, epoch: l.epoch, at: at}
	records := []journal.Record{{Kind: journal.KindRegister, UID: uid, Host: req.Host, Session: req.Session, Root: root, Epoch: l.epoch, At: at}}
	if !seen && !(req.Fresh && root == req.Session) {
		records = append(records, c.raise(lk, journal.LegUntrusted, proto.SourceUnknownSession, at)...)
	}
	if err := c.commit(records); err != nil {
		return nil, err
	}
	return &proto.RegisterResponse{Version: proto.Version, Legs: l.legs}, nil
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
	if err := c.commit(c.raise(lk, leg, req.Source, c.now().Unix())); err != nil {
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
	if err := c.commit(c.raise(lk, journal.LegUntrusted, req.Source, c.now().Unix())); err != nil {
		return nil, err
	}
	return nil, fail(proto.CodeUnavailable)
}
