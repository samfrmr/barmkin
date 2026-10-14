package monitor

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func register(t *testing.T, h http.Handler, body string) (int, string) {
	t.Helper()
	return post(t, h, http.MethodPost, PathRegister, body)
}

func presence(t *testing.T, h http.Handler, body string) DecideResponse {
	t.Helper()
	status, raw := post(t, h, http.MethodPost, PathPresence, body)
	return InterpretDecide(status, []byte(raw))
}

const callA = `{"version":1,"session":"sess-a","call":"toolu_01A"}`

func TestPresenceAdmitsOneRegisteredCall(t *testing.T) {
	s, _ := newTestServer(t)

	if got := presence(t, s, callA); got.Decision != Deny || got.Reason != ReasonUnregistered {
		t.Fatalf("before register: %+v", got)
	}
	if status, raw := register(t, s, callA); status != http.StatusOK || !strings.Contains(raw, `"registered":true`) {
		t.Fatalf("register: HTTP %d %s", status, raw)
	}
	other := `{"version":1,"session":"sess-b","call":"toolu_01A"}`
	if got := presence(t, s, other); got.Decision != Deny || got.Reason != ReasonUnregistered {
		t.Fatalf("same call in another session: %+v", got)
	}
	if got := presence(t, s, callA); got.Decision != Allow || got.Reason != ReasonOK {
		t.Fatalf("registered: %+v", got)
	}
	if got := presence(t, s, callA); got.Decision != Deny || got.Reason != ReasonUnregistered {
		t.Fatalf("replayed: %+v", got)
	}
}

func TestPresenceExpires(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	s.SetPresenceTTL(time.Second)

	register(t, s, callA)
	now = now.Add(time.Second)
	if got := presence(t, s, callA); got.Decision != Deny || got.Reason != ReasonExpired {
		t.Fatalf("at expiry: %+v", got)
	}
	if got := presence(t, s, callA); got.Decision != Deny || got.Reason != ReasonUnregistered {
		t.Fatalf("after expiry: %+v", got)
	}
}

func TestPresenceRejectsBadRequests(t *testing.T) {
	s, _ := newTestServer(t)
	register(t, s, callA)
	cases := []struct {
		name, body string
		reason     Reason
	}{
		{"invalid json", `{"version":1,`, ReasonMalformedRequest},
		{"unknown field", `{"version":1,"session":"sess-a","call":"toolu_01A","tool":"Bash"}`, ReasonMalformedRequest},
		{"missing call", `{"version":1,"session":"sess-a"}`, ReasonMalformedRequest},
		{"bad call", `{"version":1,"session":"sess-a","call":"rm -rf /"}`, ReasonMalformedRequest},
		{"bad session", `{"version":1,"session":"","call":"toolu_01A"}`, ReasonMalformedRequest},
		{"future version", `{"version":2,"session":"sess-a","call":"toolu_01A"}`, ReasonUnsupportedVersion},
		{"decide-shaped", `{"version":1,"session":"sess-a","operation":"routine"}`, ReasonMalformedRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for _, path := range []string{PathRegister, PathPresence} {
				status, raw := post(t, s, http.MethodPost, path, c.body)
				if status == http.StatusOK || !strings.Contains(raw, `"reason":"`+string(c.reason)+`"`) {
					t.Fatalf("%s: HTTP %d %s, want reason %s", path, status, raw, c.reason)
				}
			}
		})
	}
	// None of the rejected requests consumed or replaced the registration.
	if got := presence(t, s, callA); got.Decision != Allow {
		t.Fatalf("registration lost: %+v", got)
	}
}

func TestPresenceCapacity(t *testing.T) {
	s, _ := newTestServer(t)
	now := time.Unix(1_000_000, 0)
	s.now = func() time.Time { return now }
	for i := range MaxPresence {
		if status, raw := register(t, s, fmt.Sprintf(`{"version":1,"session":"s","call":"c%d"}`, i)); status != http.StatusOK {
			t.Fatalf("register %d: HTTP %d %s", i, status, raw)
		}
	}
	status, raw := register(t, s, callA)
	if status == http.StatusOK || !strings.Contains(raw, string(ReasonCapacityExceeded)) {
		t.Fatalf("over capacity: HTTP %d %s", status, raw)
	}
	now = now.Add(PresenceTTL) // every registration has expired and can be swept
	if status, raw := register(t, s, callA); status != http.StatusOK {
		t.Fatalf("after expiry: HTTP %d %s", status, raw)
	}
}

func TestPresenceDeniesWhenDegraded(t *testing.T) {
	s, _ := newTestServer(t)
	register(t, s, callA)
	s.journal.f.Close()
	post(t, s, http.MethodPost, PathTaint, `{"version":1,"session":"sess-z","source":"untrusted-input"}`)
	if got := presence(t, s, callA); got.Decision != Deny || got.Reason != ReasonJournalFailure {
		t.Fatalf("degraded: %+v", got)
	}
}

func TestClientPresenceOverSocket(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "m.sock")
	j, records := openTestJournal(t, filepath.Join(dir, "taint.journal"))
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := NewHTTPServer(NewServer(j, records))
	go srv.Serve(ln)
	ctx := context.Background()
	c := NewClient(sock, time.Second)

	if got := c.Presence(ctx, "sess-a", "toolu_01A"); got.Decision != Deny || got.Reason != ReasonUnregistered {
		t.Fatalf("unregistered: %+v", got)
	}
	if _, err := c.Register(ctx, "sess-a", "toolu_01A"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, "sess-a", "not a token"); err == nil {
		t.Fatal("malformed register reported success")
	}
	if got := c.Presence(ctx, "sess-a", "toolu_01A"); got.Decision != Allow {
		t.Fatalf("registered: %+v", got)
	}

	srv.Close()
	if got := c.Presence(ctx, "sess-a", "toolu_01B"); got.Decision != Deny || got.Reason != ReasonMonitorUnavailable {
		t.Fatalf("stopped: %+v", got)
	}
	if _, err := c.Register(ctx, "sess-a", "toolu_01B"); err == nil {
		t.Fatal("register against a stopped monitor reported success")
	}
}
