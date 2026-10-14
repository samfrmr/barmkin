package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Daviey/barmkin/monitor"
)

// shortGateTimes shrinks the gate's waits so tests stay fast.
func shortGateTimes(t *testing.T) {
	t.Helper()
	saved := gateTimes
	gateTimes = gateTiming{
		deadline: 2 * time.Second,
		stdin:    300 * time.Millisecond,
		wait:     400 * time.Millisecond,
		request:  200 * time.Millisecond,
		poll:     10 * time.Millisecond,
	}
	t.Cleanup(func() { gateTimes = saved })
}

// gateSocketDir returns a directory whose paths fit in a Unix socket address.
func gateSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bmk")
	if err == nil && len(dir) > 80 {
		os.RemoveAll(dir)
		dir, err = os.MkdirTemp("/tmp", "bmk")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// startMonitor serves a real monitor and returns its socket path.
func startMonitor(t *testing.T, ttl time.Duration) string {
	t.Helper()
	dir := gateSocketDir(t)
	j, records, err := monitor.OpenJournal(filepath.Join(dir, "taint.journal"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "m.sock")
	ln, err := monitor.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	s := monitor.NewServer(j, records)
	s.SetPresenceTTL(ttl)
	srv := monitor.NewHTTPServer(s)
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close(); j.Close() })
	return sock
}

// startFakeMonitor answers every request on a Unix socket with handler.
func startFakeMonitor(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(gateSocketDir(t), "fake.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func hookInput(session, call string) string {
	b, _ := json.Marshal(map[string]any{
		"session_id":      session,
		"tool_use_id":     call,
		"hook_event_name": "PreToolUse",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "ls"},
		"cwd":             "/tmp",
	})
	return string(b)
}

// gate runs the gate and returns its exit code and stderr.
func gate(t *testing.T, sock, stdin string) (int, string) {
	t.Helper()
	return gateWith(t, []string{"-socket", sock}, strings.NewReader(stdin), func(string) string { return "" })
}

func gateWith(t *testing.T, args []string, stdin io.Reader, getenv func(string) string) (int, string) {
	t.Helper()
	var stderr bytes.Buffer
	code := runGate(args, stdin, &stderr, getenv)
	if code != 0 && code != 2 {
		t.Fatalf("gate exit %d: Claude Code would let the call proceed", code)
	}
	return code, stderr.String()
}

func wantDeny(t *testing.T, code int, stderr string, reason monitor.Reason) {
	t.Helper()
	if code != 2 || !strings.Contains(stderr, `"decision":"deny","reason":"`+string(reason)+`"`) {
		t.Fatalf("exit %d %q, want deny/%s", code, stderr, reason)
	}
}

func register(t *testing.T, sock, session, call string) {
	t.Helper()
	if _, err := monitor.NewClient(sock, time.Second).Register(context.Background(), session, call); err != nil {
		t.Fatal(err)
	}
}

func TestGateAllowsRegisteredCallOnce(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	register(t, sock, "sess-a", "toolu_01A")

	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 || stderr != "" {
		t.Fatalf("registered call: exit %d %q", code, stderr)
	}
	code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A"))
	wantDeny(t, code, stderr, monitor.ReasonUnregistered)
}

func TestGateDeniesUnregisteredCall(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	register(t, sock, "sess-a", "toolu_01A")

	start := time.Now()
	code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01B"))
	wantDeny(t, code, stderr, monitor.ReasonUnregistered)
	if elapsed := time.Since(start); elapsed < gateTimes.wait/2 || elapsed > gateTimes.deadline {
		t.Fatalf("gate gave up after %s, want about %s", elapsed, gateTimes.wait)
	}
}

func TestGateWaitsForParallelShim(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	go func() {
		time.Sleep(100 * time.Millisecond)
		monitor.NewClient(sock, time.Second).Register(context.Background(), "sess-a", "toolu_01A")
	}()
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("late registration: exit %d %q", code, stderr)
	}
}

func TestGateDeniesExpiredCall(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, 50*time.Millisecond)
	register(t, sock, "sess-a", "toolu_01A")
	time.Sleep(100 * time.Millisecond)
	code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A"))
	wantDeny(t, code, stderr, monitor.ReasonExpired)
}

func TestGateDeniesMalformedInput(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	register(t, sock, "sess-a", "toolu_01A")
	cases := map[string]string{
		"empty":             ``,
		"not json":          `Bash ls`,
		"array":             `[1]`,
		"missing call":      `{"session_id":"sess-a","tool_name":"Bash"}`,
		"missing session":   `{"tool_use_id":"toolu_01A","tool_name":"Bash"}`,
		"malformed call":    hookInput("sess-a", "toolu 01A"),
		"malformed session": hookInput("sess a", "toolu_01A"),
		"wrong type":        `{"session_id":"sess-a","tool_use_id":7}`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			code, stderr := gate(t, sock, in)
			wantDeny(t, code, stderr, monitor.ReasonMalformedRequest)
		})
	}
	// None of them reached or consumed the registration.
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("registration lost: exit %d %q", code, stderr)
	}
}

func TestGateDeniesStalledStdin(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	r, w := io.Pipe()
	defer w.Close()
	code, stderr := gateWith(t, []string{"-socket", sock}, r, func(string) string { return "" })
	wantDeny(t, code, stderr, monitor.ReasonMalformedRequest)
}

func TestGateDeniesOversizedInput(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	big := io.MultiReader(strings.NewReader(`{"session_id":"sess-a","tool_use_id":"toolu_01A","x":"`),
		io.LimitReader(zeros{}, gateMaxInput))
	code, stderr := gateWith(t, []string{"-socket", sock}, big, func(string) string { return "" })
	wantDeny(t, code, stderr, monitor.ReasonMalformedRequest)
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = '0'
	}
	return len(p), nil
}

func TestGateDeniesUnreachableMonitor(t *testing.T) {
	shortGateTimes(t)
	absent := filepath.Join(gateSocketDir(t), "absent.sock")
	code, stderr := gate(t, absent, hookInput("sess-a", "toolu_01A"))
	wantDeny(t, code, stderr, monitor.ReasonMonitorUnavailable)
}

func TestGateDeniesWithoutConfiguration(t *testing.T) {
	shortGateTimes(t)
	in := hookInput("sess-a", "toolu_01A")
	noEnv := func(string) string { return "" }

	code, stderr := gateWith(t, nil, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, monitor.ReasonMonitorUnavailable)
	code, stderr = gateWith(t, []string{"-bogus"}, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, monitor.ReasonMalformedRequest)
	code, stderr = gateWith(t, []string{"-socket", "x", "extra"}, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, monitor.ReasonMalformedRequest)
}

func TestGateSocketFromEnvironment(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, monitor.PresenceTTL)
	register(t, sock, "sess-a", "toolu_01A")
	env := func(k string) string {
		if k == envMonitorSocket {
			return sock
		}
		return ""
	}
	if code, stderr := gateWith(t, nil, strings.NewReader(hookInput("sess-a", "toolu_01A")), env); code != 0 {
		t.Fatalf("socket from env: exit %d %q", code, stderr)
	}
}

func TestGateDeniesMalformedOrStalledMonitor(t *testing.T) {
	shortGateTimes(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		reason  monitor.Reason
	}{
		{"allow without version", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `{"decision":"allow","reason":"ok"}`)
		}, monitor.ReasonMalformedResponse},
		{"allow from future version", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `{"version":2,"decision":"allow","reason":"ok"}`)
		}, monitor.ReasonMalformedResponse},
		{"allow with error status", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, `{"version":1,"decision":"allow","reason":"ok"}`)
		}, monitor.ReasonMalformedResponse},
		{"plain text", func(w http.ResponseWriter, _ *http.Request) {
			io.WriteString(w, `ok`)
		}, monitor.ReasonMalformedResponse},
		{"stalled", func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}, monitor.ReasonMonitorUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sock := startFakeMonitor(t, c.handler)
			code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A"))
			wantDeny(t, code, stderr, c.reason)
		})
	}
}

func TestGateSendsContentFreeRequests(t *testing.T) {
	shortGateTimes(t)
	var mu sync.Mutex
	var got []string
	sock := startFakeMonitor(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		got = append(got, r.URL.Path+" "+string(body))
		io.WriteString(w, `{"version":1,"decision":"allow","reason":"ok"}`)
	})
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	want := `/v1/presence {"version":1,"session":"sess-a","call":"toolu_01A"}`
	if len(got) != 1 || got[0] != want {
		t.Fatalf("requests %q, want [%q]", got, want)
	}
}

// TestGateDeadlineUnderHookTimeouts keeps the gate's hard deadline below
// the hook timeout in the shipped managed-settings recipe: a gate that
// outlives its hook timeout lets the call proceed.
func TestGateDeadlineUnderHookTimeouts(t *testing.T) {
	if gateTimes.wait+gateTimes.request > gateTimes.deadline {
		t.Fatalf("wait %s + request %s exceeds the deadline %s", gateTimes.wait, gateTimes.request, gateTimes.deadline)
	}
	data, err := os.ReadFile("plugins/claude-code/managed-settings.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, group := range settings.Hooks["PreToolUse"] {
		for _, h := range group.Hooks {
			if !strings.Contains(h.Command, "barmkin gate") {
				continue
			}
			found = true
			if group.Matcher != "*" {
				t.Errorf("gate matcher %q, want *", group.Matcher)
			}
			if limit := time.Duration(h.Timeout) * time.Second; limit < 2*gateTimes.deadline {
				t.Errorf("hook timeout %s is not comfortably above the gate deadline %s", limit, gateTimes.deadline)
			}
		}
	}
	if !found {
		t.Fatal("recipe has no PreToolUse barmkin gate hook")
	}
}

// TestClaudeGateDemo runs scripts/claude-gate-demo.sh, which builds both
// commands and drives the shim plugin's hook and the gate together.
func TestClaudeGateDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the monitor, gate and shim as subprocesses")
	}
	for _, tool := range []string{"bash", "node"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available", tool)
		}
	}
	out, err := exec.Command("bash", "scripts/claude-gate-demo.sh").CombinedOutput()
	t.Logf("demo output:\n%s", out)
	if err != nil {
		t.Fatalf("demo failed: %v", err)
	}
}

// TestShimTypeScript runs the shim plugin's own node:test suite.
func TestShimTypeScript(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	cmd := exec.Command("node", "--test", "shim.test.ts")
	cmd.Dir = "plugins/claude-code/barmkin-shim"
	out, err := cmd.CombinedOutput()
	t.Logf("node --test output:\n%s", out)
	if err != nil {
		t.Fatalf("shim tests failed: %v", err)
	}
}
