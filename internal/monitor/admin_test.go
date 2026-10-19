package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/admin"
	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// postAdmin sends one administrative request to the core, as a peer of uid.
func postAdmin(t *testing.T, c *core, path, body string, uid uint32) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	r = r.WithContext(withPeer(r.Context(), uid))
	w := httptest.NewRecorder()
	adminHandler{core: c, logf: t.Logf}.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

func adminCode(t *testing.T, status int, out []byte) admin.Code {
	t.Helper()
	if status == http.StatusOK {
		return ""
	}
	var e admin.ErrorResponse
	if err := admin.Decode(out, admin.MaxResponseBytes, &e); err != nil || e.Error.HTTPStatus() != status {
		t.Fatalf("not an administrative error: %d %s", status, out)
	}
	return e.Error
}

func clearBody(uid uint32, lineage string, epoch uint64, legs proto.Legs, reason journal.Reason) string {
	return fmt.Sprintf(`{"version":1,"uid":%d,"host":"claude_code","lineage":%q,"epoch":%d,"legs":{"untrusted":%q,"sensitive":%q},"reason":%q}`,
		uid, lineage, epoch, legs.Untrusted, legs.Sensitive, reason)
}

// clearLineage clears lineage of alice as root, and fails the test unless
// it answers code.
func clearLineage(t *testing.T, c *core, lineage string, epoch uint64, legs proto.Legs) admin.Code {
	t.Helper()
	status, out := postAdmin(t, c, admin.OpClear.Path(), clearBody(alice, lineage, epoch, legs, journal.ReasonReviewedSafe), adminUID)
	return adminCode(t, status, out)
}

func listOf(t *testing.T, c *core) []admin.Lineage {
	t.Helper()
	status, out := postAdmin(t, c, admin.OpList.Path(), `{"version":1}`, adminUID)
	var resp admin.ListResponse
	if status != http.StatusOK || admin.Decode(out, admin.MaxResponseBytes, &resp) != nil {
		t.Fatalf("list: %d %s", status, out)
	}
	return resp.Lineages
}

func lineageOf(t *testing.T, c *core, uid uint32, root string) admin.Lineage {
	t.Helper()
	for _, l := range listOf(t, c) {
		if l.UID == uid && l.Lineage == root {
			return l
		}
	}
	t.Fatalf("no lineage %s of uid %d", root, uid)
	return admin.Lineage{}
}

func preregister(t *testing.T, c *core, session, id string) proto.Code {
	t.Helper()
	_, code := call(t, c, alice, &proto.PreregisterRequest{Version: proto.Version, Host: proto.HostClaudeCode, Session: session, Call: id})
	return code
}

func gateOf(t *testing.T, c *core, session, id string) (bool, proto.Code) {
	t.Helper()
	resp, code := call(t, c, alice, &proto.GateRequest{Version: proto.Version, Host: proto.HostClaudeCode, Session: session, Call: id})
	if code != "" {
		return false, code
	}
	return resp.(*proto.GateResponse).Preregistered, ""
}

// taintedCore has alice's lineage "root", with a subagent session "child",
// both legs up, and bob's lineage "other", tainted too.
func taintedCore(t *testing.T) (*core, *memJournal) {
	t.Helper()
	c, j := testCore(t)
	now := time.Unix(1_800_000_000, 0)
	c.now = func() time.Time { return now }
	mustRegister(t, c, alice, reg("root", "root", true))
	mustRegister(t, c, alice, reg("child", "root", true))
	observe(t, c, alice, "child", proto.SourceFetch)
	now = now.Add(time.Minute)
	observe(t, c, alice, "root", proto.SourceCredential)
	mustRegister(t, c, bob, reg("other", "other", true))
	observe(t, c, bob, "other", proto.SourceMCP)
	return c, j
}

func TestAdminListShowsLineagesWithoutContent(t *testing.T) {
	c, _ := taintedCore(t)
	l := lineageOf(t, c, alice, "root")
	want := admin.Lineage{
		UID: alice, Host: proto.HostClaudeCode, Lineage: "root", Epoch: 0,
		Legs:        legsOf(proto.SourceFetch, proto.SourceCredential),
		UntrustedAt: 1_800_000_000, SensitiveAt: 1_800_000_060,
		Sessions: []admin.Session{{Session: "child", Current: true, At: 1_800_000_000}, {Session: "root", Current: true, At: 1_800_000_000}},
		Clears:   []admin.Clear{},
	}
	if fmt.Sprint(l) != fmt.Sprint(want) {
		t.Errorf("list:\n got %+v\nwant %+v", l, want)
	}
	if got := lineageOf(t, c, bob, "other").Legs; got != legsOf(proto.SourceMCP, proto.SourceNone) {
		t.Errorf("bob's lineage: %+v", got)
	}
}

func TestAdminClearLowersLegsAndKeepsHistory(t *testing.T) {
	c, j := taintedCore(t)
	before := len(j.records)
	up := legsOf(proto.SourceFetch, proto.SourceCredential)
	if code := clearLineage(t, c, "root", 0, up); code != "" {
		t.Fatalf("clear: %s", code)
	}

	got := j.records[before:]
	want := journal.Record{Kind: journal.KindClear, UID: alice, Host: proto.HostClaudeCode, Root: "root",
		Epoch: 1, Reason: journal.ReasonReviewedSafe, At: 1_800_000_060}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("journaled %+v, want just %+v", got, want)
	}
	if !slices.ContainsFunc(j.records[:before], func(r journal.Record) bool {
		return r.Kind == journal.KindRaise && r.Root == "root" && r.Source == proto.SourceFetch
	}) {
		t.Error("the cleared raise is gone from the journal")
	}

	l := lineageOf(t, c, alice, "root")
	if l.Epoch != 1 || l.Legs != clean || l.UntrustedAt != 0 || l.SensitiveAt != 0 {
		t.Errorf("after clear: %+v", l)
	}
	wantClear := admin.Clear{Epoch: 1, Reason: journal.ReasonReviewedSafe, At: 1_800_000_060, Legs: up, UntrustedAt: 1_800_000_000, SensitiveAt: 1_800_000_060}
	if len(l.Clears) != 1 || l.Clears[0] != wantClear {
		t.Errorf("history after clear: %+v, want %+v", l.Clears, wantClear)
	}
	for _, s := range l.Sessions {
		if s.Current {
			t.Errorf("session %s is current after its lineage was cleared", s.Session)
		}
	}
	if got := lineageOf(t, c, bob, "other").Legs; got != legsOf(proto.SourceMCP, proto.SourceNone) {
		t.Errorf("another lineage changed: %+v", got)
	}

	// Legs rise again in the new epoch, and a second clear keeps both.
	mustRegister(t, c, alice, reg("root", "root", false))
	observe(t, c, alice, "root", proto.SourceSkill)
	if code := clearLineage(t, c, "root", 1, legsOf(proto.SourceSkill, proto.SourceNone)); code != "" {
		t.Fatalf("second clear: %s", code)
	}
	if l := lineageOf(t, c, alice, "root"); len(l.Clears) != 2 || l.Clears[1].Legs != legsOf(proto.SourceSkill, proto.SourceNone) || l.Clears[0] != wantClear {
		t.Errorf("history after two clears: %+v", l.Clears)
	}
}

// After a clear, every session of the lineage must register again before it
// is answered, and no pre-registration made before the clear passes the
// gate.
func TestAdminClearRequiresReRegistration(t *testing.T) {
	c, j := taintedCore(t)
	for _, s := range []string{"root", "child"} {
		if code := preregister(t, c, s, "before-"+s); code != "" {
			t.Fatalf("preregister: %s", code)
		}
	}
	if code := clearLineage(t, c, "root", 0, legsOf(proto.SourceFetch, proto.SourceCredential)); code != "" {
		t.Fatalf("clear: %s", code)
	}

	h := proto.HostClaudeCode
	for _, s := range []string{"root", "child"} {
		for _, req := range []proto.Message{
			&proto.GateRequest{Version: proto.Version, Host: h, Session: s, Call: "before-" + s},
			&proto.PreregisterRequest{Version: proto.Version, Host: h, Session: s, Call: "x"},
			decideReq(s),
			&proto.ObserveRequest{Version: proto.Version, Host: h, Session: s, Source: proto.SourceMCP},
			&proto.ScreenRequest{Version: proto.Version, Host: h, Session: s, Source: proto.SourceFetch, Windows: []string{"w"}},
			&proto.StatusRequest{Version: proto.Version, Host: h, Session: s},
		} {
			if _, code := call(t, c, alice, req); code != proto.CodeUnknownSession {
				t.Errorf("%T for %s before it registered again: %q, want unknown_session", req, s, code)
			}
		}
	}
	if l := lineageOf(t, c, alice, "root"); l.Legs != clean {
		t.Fatalf("requests from stale sessions changed the legs: %+v", l.Legs)
	}

	n := len(j.records)
	if legs := mustRegister(t, c, alice, reg("root", "root", false)); legs != clean {
		t.Fatalf("register again after clear: %+v", legs)
	}
	if got := j.records[n:]; len(got) != 1 || got[0].Kind != journal.KindRegister || got[0].Epoch != 1 {
		t.Errorf("register again journaled %+v, want one register in epoch 1", got)
	}
	if ok, code := gateOf(t, c, "root", "before-root"); ok || code != "" {
		t.Errorf("a pre-registration from before the clear passed the gate: %v %q", ok, code)
	}
	if code := preregister(t, c, "root", "after"); code != "" {
		t.Fatalf("preregister after register again: %s", code)
	}
	if ok, code := gateOf(t, c, "root", "after"); !ok || code != "" {
		t.Errorf("a pre-registration after the clear: %v %q", ok, code)
	}
	n = len(j.records)
	mustRegister(t, c, alice, reg("root", "root", false))
	if len(j.records) != n {
		t.Errorf("a current session's register was journaled: %+v", j.records[n:])
	}
	if _, code := status(t, c, alice, "child"); code != proto.CodeUnknownSession {
		t.Errorf("the subagent was answered before it registered again: %q", code)
	}
	if legs := mustRegister(t, c, alice, reg("child", "root", false)); legs != clean {
		t.Errorf("subagent registers again: %+v", legs)
	}
}

// A clear must name the lineage exactly, as the operator was shown it.
func TestAdminClearSessionMismatch(t *testing.T) {
	up := legsOf(proto.SourceFetch, proto.SourceCredential)
	cases := []struct {
		name string
		body string
		want admin.Code
	}{
		{"another user's uid", clearBody(bob, "root", 0, up, journal.ReasonFalsePositive), admin.CodeNotFound},
		{"a subagent session, not the lineage", clearBody(alice, "child", 0, up, journal.ReasonFalsePositive), admin.CodeNotFound},
		{"an unknown lineage", clearBody(alice, "nobody", 0, up, journal.ReasonFalsePositive), admin.CodeNotFound},
		{"another user's lineage under alice's uid", clearBody(alice, "other", 0, legsOf(proto.SourceMCP, proto.SourceNone), journal.ReasonFalsePositive), admin.CodeNotFound},
		{"another host", strings.Replace(clearBody(alice, "root", 0, up, journal.ReasonFalsePositive), "claude_code", "opencode", 1), admin.CodeNotFound},
		{"a later epoch", clearBody(alice, "root", 1, up, journal.ReasonFalsePositive), admin.CodeMismatch},
		{"legs that have since risen", clearBody(alice, "root", 0, legsOf(proto.SourceFetch, proto.SourceNone), journal.ReasonFalsePositive), admin.CodeMismatch},
		{"another source", clearBody(alice, "root", 0, legsOf(proto.SourceMCP, proto.SourceCredential), journal.ReasonFalsePositive), admin.CodeMismatch},
		{"a free-text reason", clearBody(alice, "root", 0, up, "the user asked"), admin.CodeBadRequest},
		{"no reason", strings.Replace(clearBody(alice, "root", 0, up, journal.ReasonFalsePositive), `,"reason":"false_positive"`, "", 1), admin.CodeBadRequest},
		{"an unknown field", strings.Replace(clearBody(alice, "root", 0, up, journal.ReasonFalsePositive), `{"version":1`, `{"version":1,"force":true`, 1), admin.CodeBadRequest},
		{"another version", strings.Replace(clearBody(alice, "root", 0, up, journal.ReasonFalsePositive), `"version":1`, `"version":2`, 1), admin.CodeBadRequest},
		{"a source the leg cannot hold", clearBody(alice, "root", 0, legsOf(proto.SourceCredential, proto.SourceNone), journal.ReasonFalsePositive), admin.CodeBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, j := taintedCore(t)
			n := len(j.records)
			code, out := postAdmin(t, c, admin.OpClear.Path(), tc.body, adminUID)
			if got := adminCode(t, code, out); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
			if len(j.records) != n {
				t.Errorf("a refused clear was journaled: %+v", j.records[n:])
			}
			if legs, _ := status(t, c, alice, "root"); legs != up {
				t.Errorf("a refused clear changed the legs: %+v", legs)
			}
		})
	}
}

// inspectJournal calls onAppend inside Append, before recording, as a
// journal whose fsync has not returned.
type inspectJournal struct {
	memJournal
	onAppend func()
	fail     bool
}

func (j *inspectJournal) Append(rs ...journal.Record) error {
	j.onAppend()
	if j.fail {
		return errors.New("fsync failed")
	}
	return j.memJournal.Append(rs...)
}

// The clear record is durable before the legs fall or the clear is
// answered, and a clear the journal could not take never lowers a leg.
func TestAdminClearDurabilityOrdering(t *testing.T) {
	up := legsOf(proto.SourceFetch, proto.SourceCredential)
	t.Run("legs stay up until the journal returns", func(t *testing.T) {
		c, _ := taintedCore(t)
		var during proto.Legs
		var calls int
		ij := &inspectJournal{}
		ij.onAppend = func() {
			// Append runs under the core's lock, on the clearing goroutine.
			during = c.lineages[lineageKey{alice, proto.HostClaudeCode, "root"}].legs
			calls++
		}
		c.journal = ij
		if code := clearLineage(t, c, "root", 0, up); code != "" {
			t.Fatalf("clear: %s", code)
		}
		if calls != 1 || during != up {
			t.Errorf("legs while the clear was being journaled: %+v (%d appends), want %+v", during, calls, up)
		}
	})

	t.Run("no answer before the journal returns", func(t *testing.T) {
		c, _ := taintedCore(t)
		j := &gatedJournal{entered: make(chan struct{}, 1), release: make(chan struct{})}
		c.journal = j
		answered := make(chan admin.Code, 1)
		go func() {
			r := httptest.NewRequest(http.MethodPost, admin.OpClear.Path(), strings.NewReader(clearBody(alice, "root", 0, up, journal.ReasonReviewedSafe)))
			r = r.WithContext(withPeer(r.Context(), adminUID))
			w := httptest.NewRecorder()
			adminHandler{core: c, logf: func(string, ...any) {}}.ServeHTTP(w, r)
			answered <- admin.Code(fmt.Sprint(w.Code))
		}()
		select {
		case <-j.entered:
		case <-answered:
			t.Fatal("answered without journaling")
		case <-time.After(5 * time.Second):
			t.Fatal("never journaled")
		}
		select {
		case <-answered:
			t.Fatal("answered while the journal was still writing")
		case <-time.After(100 * time.Millisecond):
		}
		close(j.release)
		select {
		case got := <-answered:
			if got != "200" {
				t.Errorf("clear answered %s", got)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("never answered after the journal returned")
		}
	})

	t.Run("a failed append lowers nothing and degrades", func(t *testing.T) {
		c, _ := taintedCore(t)
		c.journal = &inspectJournal{onAppend: func() {}, fail: true}
		if code := clearLineage(t, c, "root", 0, up); code != admin.CodeUnavailable {
			t.Fatalf("clear with a failing journal: %q, want unavailable", code)
		}
		l := c.lineages[lineageKey{alice, proto.HostClaudeCode, "root"}]
		if l.legs != up || l.epoch != 0 || len(l.history) != 0 {
			t.Errorf("a clear that was not journaled changed the lineage: %+v", l)
		}
		if _, code := status(t, c, alice, "root"); code != proto.CodeUnavailable {
			t.Errorf("status after a failed clear: %q, want unavailable", code)
		}
		if code := clearLineage(t, c, "root", 0, up); code != admin.CodeUnavailable {
			t.Errorf("a second clear on a degraded monitor: %q", code)
		}
	})
}

// Replaying the journal, or the snapshot written at start, rebuilds the
// cleared state, the epoch, the history and which sessions must register
// again. An unclean stop still marks every lineage monitor_restart.
func TestAdminClearReplay(t *testing.T) {
	c, j := taintedCore(t)
	clearLineage(t, c, "root", 0, legsOf(proto.SourceFetch, proto.SourceCredential))
	mustRegister(t, c, alice, reg("root", "root", false))
	observe(t, c, alice, "root", proto.SourceMCP)
	want := lineageOf(t, c, alice, "root")

	for name, records := range map[string][]journal.Record{"journal": j.records, "snapshot": c.snapshot()} {
		t.Run(name, func(t *testing.T) {
			r := newCore(records, true)
			r.journal = &memJournal{}
			if got := lineageOf(t, r, alice, "root"); fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("after replay:\n got %+v\nwant %+v", got, want)
			}
			if _, code := status(t, r, alice, "child"); code != proto.CodeUnknownSession {
				t.Errorf("the stale subagent after replay: %q, want unknown_session", code)
			}
			u := newCore(records, false)
			u.journal = &memJournal{}
			got := lineageOf(t, u, alice, "root")
			if got.Legs != legsOf(proto.SourceMCP, proto.SourceNone) || len(got.Clears) != 1 || got.Epoch != 1 {
				t.Errorf("after an unclean replay: %+v", got)
			}
			if got := lineageOf(t, u, bob, "other").Legs; got != legsOf(proto.SourceMCP, proto.SourceNone) {
				t.Errorf("bob after an unclean replay: %+v", got)
			}
		})
	}
	if !slices.Equal(newCore(c.snapshot(), true).snapshot(), c.snapshot()) {
		t.Error("a snapshot with history does not survive its own replay")
	}
}

// Only root reaches the administrative handler, and the two contracts never
// answer each other's paths.
func TestAdminPathsAreSeparate(t *testing.T) {
	up := legsOf(proto.SourceFetch, proto.SourceCredential)
	body := clearBody(alice, "root", 0, up, journal.ReasonReviewedSafe)

	t.Run("non-root peers are forbidden", func(t *testing.T) {
		c, j := taintedCore(t)
		n := len(j.records)
		for _, uid := range []uint32{alice, bob, 65534} {
			for _, op := range admin.Ops {
				status, out := postAdmin(t, c, op.Path(), body, uid)
				if code := adminCode(t, status, out); code != admin.CodeForbidden {
					t.Errorf("%s from uid %d: %q, want forbidden", op, uid, code)
				}
			}
		}
		r := httptest.NewRequest(http.MethodPost, admin.OpClear.Path(), strings.NewReader(body))
		w := httptest.NewRecorder()
		adminHandler{core: c, logf: t.Logf}.ServeHTTP(w, r)
		if code := adminCode(t, w.Code, w.Body.Bytes()); code != admin.CodeForbidden {
			t.Errorf("a request with no peer: %q, want forbidden", code)
		}
		if len(j.records) != n {
			t.Errorf("a forbidden request was journaled: %+v", j.records[n:])
		}
	})

	t.Run("the client socket answers no administrative path", func(t *testing.T) {
		c, j := taintedCore(t)
		n := len(j.records)
		for _, uid := range []uint32{alice, adminUID} {
			for _, op := range admin.Ops {
				for _, path := range []string{op.Path(), "/v1/" + string(op), "/v1/admin/" + string(op)} {
					if code := postCode(t, c, path, body, &uid); code != proto.CodeBadRequest {
						t.Errorf("client socket %s from uid %d: %q, want bad_request", path, uid, code)
					}
				}
			}
		}
		if len(j.records) != n {
			t.Errorf("an administrative path on the client socket was journaled: %+v", j.records[n:])
		}
		if legs, _ := status(t, c, alice, "root"); legs != up {
			t.Errorf("legs after administrative paths on the client socket: %+v", legs)
		}
	})

	t.Run("the administrative socket answers no client operation", func(t *testing.T) {
		c, _ := taintedCore(t)
		for _, op := range proto.Ops {
			status, out := postAdmin(t, c, op.Path(), `{"version":1}`, adminUID)
			if code := adminCode(t, status, out); code != admin.CodeBadRequest {
				t.Errorf("%s on the administrative socket: %q, want bad_request", op, code)
			}
		}
		for _, path := range []string{"/admin/v1/clear/", "/admin/v2/clear", "/admin/v1/Clear", "/admin/v1/", "/admin/v1/rotate"} {
			status, out := postAdmin(t, c, path, body, adminUID)
			if code := adminCode(t, status, out); code != admin.CodeBadRequest {
				t.Errorf("%s: %q, want bad_request", path, code)
			}
		}
		r := httptest.NewRequest(http.MethodGet, admin.OpList.Path(), nil)
		r = r.WithContext(withPeer(r.Context(), adminUID))
		w := httptest.NewRecorder()
		adminHandler{core: c, logf: t.Logf}.ServeHTTP(w, r)
		if !bytes.Contains(w.Body.Bytes(), []byte(`"bad_request"`)) {
			t.Errorf("GET list: %d %s", w.Code, w.Body.Bytes())
		}
	})
}
