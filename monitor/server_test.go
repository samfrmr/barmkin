package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "taint.journal")
	j, records := openTestJournal(t, path)
	return NewServer(j, records), path
}

func post(t *testing.T, h http.Handler, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func decide(t *testing.T, h http.Handler, body string) DecideResponse {
	t.Helper()
	status, raw := post(t, h, http.MethodPost, PathDecide, body)
	return InterpretDecide(status, []byte(raw))
}

func TestConservativeDenials(t *testing.T) {
	s, _ := newTestServer(t)
	cases := []struct {
		name, method, path, body string
		reason                   Reason
	}{
		{"invalid json", "POST", PathDecide, `{"version":1,`, ReasonMalformedRequest},
		{"empty body", "POST", PathDecide, ``, ReasonMalformedRequest},
		{"not an object", "POST", PathDecide, `[1]`, ReasonMalformedRequest},
		{"null", "POST", PathDecide, `null`, ReasonMalformedRequest},
		{"unknown field", "POST", PathDecide, `{"version":1,"session":"s","operation":"routine","command":"ls"}`, ReasonMalformedRequest},
		{"case-variant key", "POST", PathDecide, `{"Version":1,"session":"s","operation":"routine"}`, ReasonMalformedRequest},
		{"duplicate key", "POST", PathDecide, `{"version":1,"session":"s","operation":"protected","operation":"routine"}`, ReasonMalformedRequest},
		{"trailing data", "POST", PathDecide, `{"version":1,"session":"s","operation":"routine"}{}`, ReasonMalformedRequest},
		{"wrong type", "POST", PathDecide, `{"version":"1","session":"s","operation":"routine"}`, ReasonMalformedRequest},
		{"oversized", "POST", PathDecide, `{"version":1,"session":"s","operation":"routine","x":"` + strings.Repeat("a", MaxBodyBytes) + `"}`, ReasonMalformedRequest},
		{"wrong method", "GET", PathDecide, ``, ReasonMalformedRequest},
		{"missing version", "POST", PathDecide, `{"session":"s","operation":"routine"}`, ReasonUnsupportedVersion},
		{"future version", "POST", PathDecide, `{"version":2,"session":"s","operation":"routine"}`, ReasonUnsupportedVersion},
		{"bad session", "POST", PathDecide, `{"version":1,"session":"rm -rf /","operation":"routine"}`, ReasonMalformedRequest},
		{"empty session", "POST", PathDecide, `{"version":1,"session":"","operation":"routine"}`, ReasonMalformedRequest},
		{"unknown operation", "POST", PathDecide, `{"version":1,"session":"s","operation":"launch"}`, ReasonUnknownOperation},
		{"unknown endpoint", "POST", "/v1/override", `{"version":1}`, ReasonUnknownEndpoint},
		{"unversioned path", "POST", "/decide", `{"version":1,"session":"s","operation":"routine"}`, ReasonUnknownEndpoint},
		{"future path", "POST", "/v2/decide", `{"version":2,"session":"s","operation":"routine"}`, ReasonUnknownEndpoint},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			status, raw := post(t, s, c.method, c.path, c.body)
			got := InterpretDecide(status, []byte(raw))
			if got.Decision != Deny || got.Reason != c.reason {
				t.Fatalf("got %+v (HTTP %d), want deny/%s", got, status, c.reason)
			}
			if status == http.StatusOK {
				t.Fatalf("HTTP 200 for a rejected request")
			}
		})
	}
}

func TestTaintRejectsBadRequests(t *testing.T) {
	s, path := newTestServer(t)
	cases := map[string]string{
		"unknown source":  `{"version":1,"session":"s","source":"vibes"}`,
		"unknown field":   `{"version":1,"session":"s","source":"untrusted-input","note":"x"}`,
		"bad version":     `{"version":0,"session":"s","source":"untrusted-input"}`,
		"bad session":     `{"version":1,"session":"a b","source":"untrusted-input"}`,
		"malformed json":  `{`,
		"decide-shaped":   `{"version":1,"session":"s","operation":"protected"}`,
		"missing session": `{"version":1,"source":"untrusted-input"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			status, raw := post(t, s, http.MethodPost, PathTaint, body)
			if status == http.StatusOK || strings.Contains(raw, `"tainted":true`) {
				t.Fatalf("HTTP %d %s", status, raw)
			}
		})
	}
	if data, _ := os.ReadFile(path); len(data) != 0 {
		t.Fatalf("rejected taints reached the journal: %q", data)
	}
}

func TestTaintDeniesProtectedOnly(t *testing.T) {
	s, _ := newTestServer(t)
	protected := `{"version":1,"session":"sess-a","operation":"protected"}`
	routine := `{"version":1,"session":"sess-a","operation":"routine"}`
	other := `{"version":1,"session":"sess-b","operation":"protected"}`

	if got := decide(t, s, protected); got.Decision != Allow {
		t.Fatalf("clean session protected: %+v", got)
	}
	status, raw := post(t, s, http.MethodPost, PathTaint, `{"version":1,"session":"sess-a","source":"untrusted-input"}`)
	if status != http.StatusOK || !strings.Contains(raw, `"tainted":true`) {
		t.Fatalf("taint: HTTP %d %s", status, raw)
	}
	if got := decide(t, s, protected); got.Decision != Deny || got.Reason != ReasonTainted {
		t.Fatalf("tainted session protected: %+v", got)
	}
	if got := decide(t, s, routine); got.Decision != Allow {
		t.Fatalf("tainted session routine: %+v", got)
	}
	if got := decide(t, s, other); got.Decision != Allow {
		t.Fatalf("other session protected: %+v", got)
	}
}

func TestJournalFailureDeniesEverything(t *testing.T) {
	s, _ := newTestServer(t)
	s.journal.f.Close() // the next append fails

	status, _ := post(t, s, http.MethodPost, PathTaint, `{"version":1,"session":"sess-a","source":"untrusted-input"}`)
	if status != http.StatusServiceUnavailable {
		t.Fatalf("taint with failing journal: HTTP %d", status)
	}
	for _, body := range []string{
		`{"version":1,"session":"sess-a","operation":"protected"}`,
		`{"version":1,"session":"sess-z","operation":"routine"}`,
	} {
		if got := decide(t, s, body); got.Decision != Deny || got.Reason != ReasonJournalFailure {
			t.Fatalf("%s: %+v", body, got)
		}
	}
}

func TestInterpretDecide(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		want   Decision
	}{
		{"well-formed allow", 200, `{"version":1,"decision":"allow","reason":"ok"}`, Allow},
		{"allow with error status", 500, `{"version":1,"decision":"allow","reason":"ok"}`, Deny},
		{"allow from future version", 200, `{"version":2,"decision":"allow","reason":"ok"}`, Deny},
		{"unknown decision", 200, `{"version":1,"decision":"maybe","reason":"ok"}`, Deny},
		{"missing reason", 200, `{"version":1,"decision":"allow"}`, Deny},
		{"extra field", 200, `{"version":1,"decision":"allow","reason":"ok","x":1}`, Deny},
		{"trailing data", 200, `{"version":1,"decision":"allow","reason":"ok"}x`, Deny},
		{"empty", 200, ``, Deny},
		{"html", 200, `<html>ok</html>`, Deny},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := InterpretDecide(c.status, []byte(c.body)); got.Decision != c.want {
				t.Fatalf("got %+v, want %s", got, c.want)
			}
		})
	}
}

// shortTempDir returns a directory whose paths fit in a Unix socket address.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bmk")
	if err != nil {
		t.Fatal(err)
	}
	if len(dir) > 80 {
		os.RemoveAll(dir)
		if dir, err = os.MkdirTemp("/tmp", "bmk"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

func TestClientUnavailableDenies(t *testing.T) {
	sock := filepath.Join(shortTempDir(t), "absent.sock")
	c := NewClient(sock, 500*time.Millisecond)
	got := c.Decide(context.Background(), "sess-a", OpRoutine)
	if got.Decision != Deny || got.Reason != ReasonMonitorUnavailable {
		t.Fatalf("got %+v", got)
	}
	if _, err := c.Taint(context.Background(), "sess-a", SourceUntrustedInput); err == nil {
		t.Fatal("taint against an absent monitor reported success")
	}
}

func TestClientServerOverSocketWithRestart(t *testing.T) {
	dir := shortTempDir(t)
	sock := filepath.Join(dir, "m.sock")
	journalPath := filepath.Join(dir, "taint.journal")
	ctx := context.Background()

	start := func() func() {
		j, records, err := OpenJournal(journalPath)
		if err != nil {
			t.Fatal(err)
		}
		ln, err := Listen(sock)
		if err != nil {
			t.Fatal(err)
		}
		srv := NewHTTPServer(NewServer(j, records))
		go srv.Serve(ln)
		return func() { srv.Close(); j.Close() }
	}

	stop := start()
	c := NewClient(sock, time.Second)
	if fi, err := os.Stat(sock); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	if got := c.Decide(ctx, "sess-a", OpProtected); got.Decision != Allow {
		t.Fatalf("before taint: %+v", got)
	}
	if _, err := c.Taint(ctx, "sess-a", SourceUntrustedInput); err != nil {
		t.Fatal(err)
	}
	stop()

	if got := c.Decide(ctx, "sess-a", OpRoutine); got.Decision != Deny || got.Reason != ReasonMonitorUnavailable {
		t.Fatalf("while stopped: %+v", got)
	}

	stop = start() // the stale socket file is replaced
	defer stop()
	if got := c.Decide(ctx, "sess-a", OpProtected); got.Decision != Deny || got.Reason != ReasonTainted {
		t.Fatalf("after restart: %+v", got)
	}
	if got := c.Decide(ctx, "sess-b", OpProtected); got.Decision != Allow {
		t.Fatalf("other session after restart: %+v", got)
	}
}

func TestListenRefusesNonSocket(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "not-a-socket")
	os.WriteFile(path, []byte("keep me"), 0o600)
	if ln, err := Listen(path); err == nil {
		ln.Close()
		t.Fatal("Listen replaced a regular file")
	}
	if data, _ := os.ReadFile(path); string(data) != "keep me" {
		t.Fatal("regular file was modified")
	}
}
