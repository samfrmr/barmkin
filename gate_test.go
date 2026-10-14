package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	imonitor "github.com/Daviey/barmkin/internal/monitor"
	"github.com/Daviey/barmkin/internal/proto"
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

// monitorDeployment lays out a root-managed monitor deployment for the
// current user (internal/monitor's Start checks it), under a short path
// that fits a socket address.
func monitorDeployment(t *testing.T, ttl time.Duration) imonitor.Config {
	t.Helper()
	base := gateSocketDir(t)
	for dir, mode := range map[string]os.FileMode{"run": 0o750, "state": 0o700} {
		p := filepath.Join(base, dir)
		if err := os.Mkdir(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	return imonitor.Config{
		Socket:         filepath.Join(base, "run", "monitor.sock"),
		StateDir:       filepath.Join(base, "state"),
		ClientGroup:    g.Name,
		PreregisterTTL: ttl,
	}
}

// serveMonitor serves a real barmkin monitor (internal/monitor) until the
// returned stop is called or the test ends.
func serveMonitor(t *testing.T, cfg imonitor.Config) (stop func()) {
	t.Helper()
	m, err := imonitor.Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Serve(ctx) }()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			cancel()
			if err := <-done; err != nil {
				t.Errorf("monitor: %v", err)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// startMonitor serves a real barmkin monitor and returns its socket path.
func startMonitor(t *testing.T, ttl time.Duration) string {
	t.Helper()
	cfg := monitorDeployment(t, ttl)
	serveMonitor(t, cfg)
	return cfg.Socket
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

func wantDeny(t *testing.T, code int, stderr string, reason gateReason) {
	t.Helper()
	if code != 2 || !strings.Contains(stderr, `"decision":"deny","reason":"`+string(reason)+`"`) {
		t.Fatalf("exit %d %q, want deny/%s", code, stderr, reason)
	}
}

// post sends one contract request to the monitor as a shim does, and
// decodes its success response into resp.
func post(t *testing.T, sock string, op proto.Op, req, resp proto.Message) {
	t.Helper()
	if err := tryPost(sock, op, req, resp); err != nil {
		t.Fatal(err)
	}
}

func tryPost(sock string, op proto.Op, req, resp proto.Message) error {
	body, err := proto.Encode(req)
	if err != nil {
		return err
	}
	c := http.Client{Timeout: time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}}
	r, err := c.Post("http://barmkin"+op.Path(), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, _ := io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d %s", op, r.StatusCode, data)
	}
	if err := proto.Decode(data, resp); err != nil {
		return fmt.Errorf("%s: %v in %s", op, err, data)
	}
	return nil
}

func preregisterRequest(session, call string) *proto.PreregisterRequest {
	return &proto.PreregisterRequest{Version: proto.Version, Host: proto.HostClaudeCode, Session: session, Call: call}
}

// registerSession registers a fresh, sandboxed session, as the shim does
// at session start.
func registerSession(t *testing.T, sock, session string) {
	t.Helper()
	post(t, sock, proto.OpRegister, &proto.RegisterRequest{
		Version: proto.Version, Host: proto.HostClaudeCode, Session: session, Root: session, Fresh: true,
		Posture: proto.Posture{SandboxEnabled: true},
	}, &proto.RegisterResponse{})
}

// register pre-registers a call in a registered session, as the shim does
// from session.append, registering the session first.
func register(t *testing.T, sock, session, call string) {
	t.Helper()
	registerSession(t, sock, session)
	post(t, sock, proto.OpPreregister, preregisterRequest(session, call), &proto.PreregisterResponse{})
}

func TestGateAllowsRegisteredCallOnce(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	register(t, sock, "sess-a", "toolu_01A")

	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 || stderr != "" {
		t.Fatalf("registered call: exit %d %q", code, stderr)
	}
	code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A"))
	wantDeny(t, code, stderr, gateUnregistered)
}

func TestGateDeniesUnregisteredCall(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	register(t, sock, "sess-a", "toolu_01A")

	start := time.Now()
	code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01B"))
	wantDeny(t, code, stderr, gateUnregistered)
	if elapsed := time.Since(start); elapsed < gateTimes.wait/2 || elapsed > gateTimes.deadline {
		t.Fatalf("gate gave up after %s, want about %s", elapsed, gateTimes.wait)
	}
}

func TestGateWaitsForLateRegistration(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	registerSession(t, sock, "sess-a")
	go func() {
		time.Sleep(100 * time.Millisecond)
		tryPost(sock, proto.OpPreregister, preregisterRequest("sess-a", "toolu_01A"), &proto.PreregisterResponse{})
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
	wantDeny(t, code, stderr, gateUnregistered)
}

// A session the shim never registered is unknown to the monitor: the gate
// denies at once, without waiting, and the same call id from another
// session never borrows a pre-registration.
func TestGateDeniesUnknownSession(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	register(t, sock, "sess-a", "toolu_01A")

	start := time.Now()
	code, stderr := gate(t, sock, hookInput("sess-b", "toolu_01A"))
	wantDeny(t, code, stderr, gateUnknownSession)
	if elapsed := time.Since(start); elapsed > gateTimes.wait/2 {
		t.Fatalf("unknown session took %s; it is final, not waited on", elapsed)
	}
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("the other session's call consumed it: exit %d %q", code, stderr)
	}
}

func TestGateDeniesMalformedInput(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
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
			wantDeny(t, code, stderr, gateMalformedRequest)
		})
	}
	// None of them reached or consumed the registration.
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("registration lost: exit %d %q", code, stderr)
	}
}

func TestGateDeniesStalledStdin(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	r, w := io.Pipe()
	defer w.Close()
	code, stderr := gateWith(t, []string{"-socket", sock}, r, func(string) string { return "" })
	wantDeny(t, code, stderr, gateMalformedRequest)
}

func TestGateDeniesOversizedInput(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	big := io.MultiReader(strings.NewReader(`{"session_id":"sess-a","tool_use_id":"toolu_01A","x":"`),
		io.LimitReader(zeros{}, gateMaxInput))
	code, stderr := gateWith(t, []string{"-socket", sock}, big, func(string) string { return "" })
	wantDeny(t, code, stderr, gateMalformedRequest)
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
	wantDeny(t, code, stderr, gateMonitorUnavailable)
}

func TestGateDeniesWithoutConfiguration(t *testing.T) {
	shortGateTimes(t)
	in := hookInput("sess-a", "toolu_01A")
	noEnv := func(string) string { return "" }

	code, stderr := gateWith(t, nil, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, gateMonitorUnavailable)
	code, stderr = gateWith(t, []string{"-bogus"}, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, gateMalformedRequest)
	code, stderr = gateWith(t, []string{"-socket", "x", "extra"}, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, gateMalformedRequest)
}

func TestGateSocketFromEnvironment(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
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

// With -monitor-uid, the gate asks only a monitor socket served by that
// uid, checked by the kernel's peer credentials.
func TestGatePinsMonitorUID(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	register(t, sock, "sess-a", "toolu_01A")
	noEnv := func(string) string { return "" }
	in := hookInput("sess-a", "toolu_01A")
	self := strconv.Itoa(os.Getuid())
	other := strconv.Itoa(os.Getuid() + 1)

	code, stderr := gateWith(t, []string{"-socket", sock, "-monitor-uid", other}, strings.NewReader(in), noEnv)
	wantDeny(t, code, stderr, gateMonitorUIDMismatch)
	for _, bad := range []string{"barmkin", "-1", "4294967296", "1.5"} {
		code, stderr := gateWith(t, []string{"-socket", sock, "-monitor-uid", bad}, strings.NewReader(in), noEnv)
		wantDeny(t, code, stderr, gateMalformedRequest)
	}
	// Neither consumed the pre-registration.
	if code, stderr := gateWith(t, []string{"-socket", sock, "-monitor-uid", self}, strings.NewReader(in), noEnv); code != 0 {
		t.Fatalf("pinned to the monitor's own uid: exit %d %q", code, stderr)
	}
}

// A deny because the shim did not register the session or the call says
// the shim is not present.
func TestGateDenySaysShimNotPresent(t *testing.T) {
	shortGateTimes(t)
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	registerSession(t, sock, "sess-a")
	for in, reason := range map[string]gateReason{
		hookInput("sess-b", "toolu_01A"): gateUnknownSession,
		hookInput("sess-a", "toolu_01A"): gateUnregistered,
	} {
		code, stderr := gate(t, sock, in)
		wantDeny(t, code, stderr, reason)
		if !strings.HasPrefix(stderr, "[barmkin] gate denied: barmkin shim not present: ") {
			t.Errorf("%s deny %q does not say the shim is not present", reason, stderr)
		}
	}
	absent := filepath.Join(gateSocketDir(t), "absent.sock")
	if _, stderr := gate(t, absent, hookInput("sess-a", "toolu_01A")); strings.Contains(stderr, "shim not present") {
		t.Errorf("an unreachable monitor blames the shim: %q", stderr)
	}
}

func TestGateDeniesMalformedOrStalledMonitor(t *testing.T) {
	shortGateTimes(t)
	reply := func(status int, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			io.WriteString(w, body)
		}
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		reason  gateReason
	}{
		{"preregistered without version", reply(200, `{"preregistered":true}`), gateMalformedResponse},
		{"preregistered from another version", reply(200, `{"version":2,"preregistered":true}`), gateVersionMismatch},
		{"preregistered with an unknown field", reply(200, `{"version":1,"preregistered":true,"allow":true}`), gateMalformedResponse},
		{"preregistered with an error status", reply(500, `{"version":1,"preregistered":true}`), gateMalformedResponse},
		{"error code with the wrong status", reply(503, `{"version":1,"error":"unknown_session"}`), gateMalformedResponse},
		{"version mismatch error", reply(400, `{"version":1,"error":"version_mismatch"}`), gateVersionMismatch},
		{"unavailable error", reply(503, `{"version":1,"error":"unavailable"}`), gateMonitorUnavailable},
		{"plain text", reply(200, `ok`), gateMalformedResponse},
		{"never preregistered", reply(200, `{"version":1,"preregistered":false}`), gateUnregistered},
		{"stalled", func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}, gateMonitorUnavailable},
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
		io.WriteString(w, `{"version":1,"preregistered":true}`)
	})
	if code, stderr := gate(t, sock, hookInput("sess-a", "toolu_01A")); code != 0 {
		t.Fatalf("exit %d %q", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	want := `/v1/gate {"version":1,"host":"claude_code","session":"sess-a","call":"toolu_01A"}`
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

// TestClaudeGateDemo runs scripts/claude-gate-demo.sh, which builds
// barmkin, serves `barmkin monitor`, and drives shim-style registrations
// and the gate together.
func TestClaudeGateDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the monitor and gate as subprocesses")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := exec.Command("bash", "scripts/claude-gate-demo.sh").CombinedOutput()
	t.Logf("demo output:\n%s", out)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 77 {
		t.Skip("demo prerequisites missing")
	}
	if err != nil {
		t.Fatalf("demo failed: %v", err)
	}
}

// TestClaudeLockLab runs scripts/claude-lock-lab.sh, the live Claude Code
// lab for the full managed lock. It needs claude 2.1.x, bwrap, socat and
// user namespaces, and takes over a minute, so it runs only when
// BARMKIN_CLAUDE_LAB=1.
func TestClaudeLockLab(t *testing.T) {
	if os.Getenv("BARMKIN_CLAUDE_LAB") != "1" {
		t.Skip("set BARMKIN_CLAUDE_LAB=1 to run the live Claude Code lab")
	}
	out, err := exec.Command("bash", "scripts/claude-lock-lab.sh").CombinedOutput()
	t.Logf("lab output:\n%s", out)
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 77 {
		t.Skip("lab prerequisites missing")
	}
	if err != nil {
		t.Fatalf("lab failed: %v", err)
	}
}

// TestShimMonitorContract runs the shim's monitor client code
// (plugins/claude-code/monitor-contract.test.ts, under node) against a
// real barmkin monitor. The shim's own suite runs under `claude plugin
// test` against an in-memory monitor; this test holds that monitor's
// decide to the real one.
func TestShimMonitorContract(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	sock := startMonitor(t, imonitor.DefaultPreregisterTTL)
	cmd := exec.Command("node", "--test", "monitor-contract.test.ts")
	cmd.Dir = "plugins/claude-code"
	cmd.Env = append(os.Environ(), "BARMKIN_TEST_MONITOR_SOCKET="+sock)
	out, err := cmd.CombinedOutput()
	t.Logf("node --test output:\n%s", out)
	if err != nil {
		t.Fatalf("shim contract tests failed: %v", err)
	}
	if !bytes.Contains(out, []byte("skipped 0")) {
		t.Fatal("contract tests were skipped")
	}
}

// TestShimProtoMatchesCommon keeps the shim's copy of the contract's
// TypeScript mirror identical to shims/common/proto.ts, the copy tested
// against the shared fixtures. A plugin is installed as its own folder, so
// it carries its own copy.
func TestShimProtoMatchesCommon(t *testing.T) {
	common, err := os.ReadFile("shims/common/proto.ts")
	if err != nil {
		t.Fatal(err)
	}
	shim, err := os.ReadFile("plugins/claude-code/barmkin-shim/hooks/lib/proto.ts")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(common, shim) {
		t.Fatal("plugins/claude-code/barmkin-shim/hooks/lib/proto.ts differs from shims/common/proto.ts; copy it over")
	}
}

// TestShimTaintSurvivesMonitorRestart walks the requests the shim sends
// across a monitor restart: the session it registered keeps its taint, a
// re-register (the shim's answer to any unknown_session) cannot lower it,
// and the call it guards is still denied.
func TestShimTaintSurvivesMonitorRestart(t *testing.T) {
	cfg := monitorDeployment(t, imonitor.DefaultPreregisterTTL)
	stop := serveMonitor(t, cfg)
	sock := cfg.Socket
	scoped := func() (int, proto.Host, string) { return proto.Version, proto.HostClaudeCode, "sess-r" }
	registerSession(t, sock, "sess-r")
	v, h, s := scoped()
	post(t, sock, proto.OpObserve, &proto.ObserveRequest{Version: v, Host: h, Session: s, Source: proto.SourceFetch}, &proto.ObserveResponse{})
	stop()

	serveMonitor(t, cfg)
	var reg proto.RegisterResponse
	post(t, sock, proto.OpRegister, &proto.RegisterRequest{Version: v, Host: h, Session: s, Root: s, Posture: proto.Posture{SandboxEnabled: true}}, &reg)
	if reg.Legs.Untrusted != proto.SourceFetch {
		t.Fatalf("legs after restart %+v, want the fetch taint kept", reg.Legs)
	}
	var dec proto.DecideResponse
	post(t, sock, proto.OpDecide, &proto.DecideRequest{Version: v, Host: h, Session: s, Classes: []proto.Class{proto.ClassShellOutward}}, &dec)
	if dec.Verdict != proto.VerdictDeny {
		t.Fatalf("decide after restart %+v, want deny", dec)
	}
}

// TestManagedRecipeFullLock pins the full managed lock in the shipped
// recipe and the shape of the shim that lets it run under that lock. Under
// allowManagedHooksOnly, Claude Code 2.1.x runs only managed hooks and
// managed plugins' hooks modules; prependPlugins skips a listed plugin that
// has no hooks module, and a plugin's command hooks run only after the
// managed gate has already denied. scripts/claude-lock-lab.sh shows all of
// this in a live session.
func TestManagedRecipeFullLock(t *testing.T) {
	data, err := os.ReadFile("plugins/claude-code/managed-settings.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var s struct {
		AllowManagedHooksOnly *bool    `json:"allowManagedHooksOnly"`
		PrependPlugins        []string `json:"prependPlugins"`
		Sandbox               struct {
			Enabled                  *bool  `json:"enabled"`
			FailIfUnavailable        *bool  `json:"failIfUnavailable"`
			AllowUnsandboxedCommands *bool  `json:"allowUnsandboxedCommands"`
			BwrapPath                string `json:"bwrapPath"`
			SocatPath                string `json:"socatPath"`
			Network                  struct {
				AllowAllUnixSockets *bool `json:"allowAllUnixSockets"`
			} `json:"network"`
		} `json:"sandbox"`
		Env                    map[string]string `json:"env"`
		EnabledPlugins         map[string]bool   `json:"enabledPlugins"`
		ExtraKnownMarketplaces map[string]struct {
			Source struct {
				Source string `json:"source"`
				Path   string `json:"path"`
			} `json:"source"`
		} `json:"extraKnownMarketplaces"`
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatal(err)
	}
	const shim = "barmkin-shim@barmkin-local"
	if s.AllowManagedHooksOnly == nil || !*s.AllowManagedHooksOnly {
		t.Error("allowManagedHooksOnly must be true")
	}
	if want := []string{shim, "cc-plugin-sec-default@builtin"}; strings.Join(s.PrependPlugins, ",") != strings.Join(want, ",") {
		t.Errorf("prependPlugins %q, want %q (sec-default must stay listed)", s.PrependPlugins, want)
	}
	if !s.EnabledPlugins[shim] {
		t.Errorf("enabledPlugins does not enable %s", shim)
	}
	if m := s.ExtraKnownMarketplaces["barmkin-local"].Source; m.Source != "directory" || !strings.HasPrefix(m.Path, "/") {
		t.Errorf("barmkin-local marketplace %+v, want an absolute directory", m)
	}
	sb := s.Sandbox
	if sb.Enabled == nil || !*sb.Enabled || sb.FailIfUnavailable == nil || !*sb.FailIfUnavailable ||
		sb.AllowUnsandboxedCommands == nil || *sb.AllowUnsandboxedCommands {
		t.Errorf("sandbox %+v, want enabled, failIfUnavailable, no unsandboxed commands", sb)
	}
	if !strings.HasPrefix(sb.BwrapPath, "/") || !strings.HasPrefix(sb.SocatPath, "/") {
		t.Errorf("sandbox bwrapPath %q and socatPath %q must be absolute", sb.BwrapPath, sb.SocatPath)
	}
	if sb.Network.AllowAllUnixSockets != nil && *sb.Network.AllowAllUnixSockets {
		t.Error("sandbox must not allow all Unix sockets: sandboxed commands could forge registrations")
	}
	sock := s.Env[envMonitorSocket]
	gateCmd := ""
	for _, g := range s.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, "barmkin gate") {
				gateCmd = h.Command
			}
		}
	}
	if sock == "" || !strings.HasSuffix(gateCmd, "-socket "+sock) {
		t.Errorf("shim socket %q and gate command %q disagree", sock, gateCmd)
	}

	hooksJSON, err := os.ReadFile("plugins/claude-code/barmkin-shim/hooks/hooks.json")
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]json.RawMessage
	if err := json.Unmarshal(hooksJSON, &h); err != nil {
		t.Fatal(err)
	}
	if _, ok := h["modules"]; !ok || len(h) != 1 {
		t.Errorf("shim hooks.json %s must name only a hooks module", hooksJSON)
	}
}
