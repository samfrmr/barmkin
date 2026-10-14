package main

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/Daviey/barmkin/internal/admin"
	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// fakeAdmin is an administrative socket that records every request and
// answers list with one tainted lineage, "root", with a subagent "child".
type fakeAdmin struct {
	socket string
	mu     sync.Mutex
	paths  []string
	clears []admin.ClearRequest
	answer admin.Code // what clear answers; "" for success
}

func newFakeAdmin(t *testing.T) *fakeAdmin {
	t.Helper()
	base, err := os.MkdirTemp("", "bmc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "admin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f := &fakeAdmin{socket: filepath.Join(dir, "admin.sock")}
	ln, err := net.Listen("unix", f.socket)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.socket, 0o600); err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: f}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

func (f *fakeAdmin) lineage() admin.Lineage {
	return admin.Lineage{
		UID: 1000, Host: proto.HostClaudeCode, Lineage: "root", Epoch: 2,
		Legs:        proto.Legs{Untrusted: proto.SourceFetch, Sensitive: proto.SourceCredential},
		UntrustedAt: 1_800_000_000, SensitiveAt: 0,
		Sessions: []admin.Session{{Session: "child", Current: true}, {Session: "root", Current: true}},
		Clears:   []admin.Clear{},
	}
}

func (f *fakeAdmin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.paths = append(f.paths, r.URL.Path)
	body, _ := io.ReadAll(r.Body)
	var out []byte
	switch r.URL.Path {
	case admin.OpList.Path():
		out, _ = admin.Encode(&admin.ListResponse{Version: admin.Version, Lineages: []admin.Lineage{f.lineage()}})
	case admin.OpClear.Path():
		var req admin.ClearRequest
		if admin.Decode(body, admin.MaxRequestBytes, &req) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.clears = append(f.clears, req)
		if f.answer != "" {
			out, _ = admin.Encode(&admin.ErrorResponse{Version: admin.Version, Error: f.answer})
			w.WriteHeader(f.answer.HTTPStatus())
			w.Write(out)
			return
		}
		l := f.lineage()
		l.Epoch, l.Legs = 3, proto.Legs{Untrusted: proto.SourceNone, Sensitive: proto.SourceNone}
		out, _ = admin.Encode(&admin.ClearResponse{Version: admin.Version, Lineage: l})
	}
	w.Write(out)
}

func (f *fakeAdmin) seen() ([]string, []admin.ClearRequest) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.paths...), append([]admin.ClearRequest(nil), f.clears...)
}

// stdinOf returns a file whose contents are typed.
func stdinOf(t *testing.T, typed string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	w.WriteString(typed)
	w.Close()
	t.Cleanup(func() { r.Close() })
	return r
}

type adminRun struct {
	code           int
	stdout, stderr string
}

// runAdmin runs monitor-admin as root at a terminal typing typed, unless
// mutate says otherwise.
func runAdmin(t *testing.T, f *fakeAdmin, typed string, mutate func(*adminEnv), args ...string) adminRun {
	t.Helper()
	var stdout, stderr bytes.Buffer
	env := adminEnv{
		stdin: stdinOf(t, typed), stdout: &stdout, stderr: &stderr,
		euid: 0, isTerminal: func(*os.File) bool { return true }, socketOwner: os.Getuid(),
	}
	if mutate != nil {
		mutate(&env)
	}
	code := runMonitorAdmin(append(append([]string(nil), args...), "-admin-socket", f.socket), env)
	return adminRun{code, stdout.String(), stderr.String()}
}

var clearArgs = []string{"clear", "-uid", "1000", "-host", "claude_code", "-lineage", "root", "-reason", "false_positive"}

func TestMonitorAdminClearConfirmed(t *testing.T) {
	f := newFakeAdmin(t)
	r := runAdmin(t, f, "root\n", nil, clearArgs...)
	if r.code != 0 {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	_, clears := f.seen()
	want := admin.ClearRequest{Version: admin.Version, UID: 1000, Host: proto.HostClaudeCode, Lineage: "root", Epoch: 2,
		Legs: proto.Legs{Untrusted: proto.SourceFetch, Sensitive: proto.SourceCredential}, Reason: journal.ReasonFalsePositive}
	if len(clears) != 1 || clears[0] != want {
		t.Fatalf("clears sent: %+v, want %+v", clears, want)
	}
	for _, s := range []string{"fetch (2027-01-15T08:00:00Z)", "credential (time unknown)", "does not remove untrusted material already in an AI\nconversation", "epoch 3", "register again"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("output lacks %q:\n%s", s, r.stdout)
		}
	}
	if n := strings.Count(r.stdout, "does not remove untrusted material"); n != 2 {
		t.Errorf("the conversation warning is shown %d times, want before and after", n)
	}
}

// Nothing is cleared without root, a terminal, a closed reason and the
// lineage id typed back; the gates before the confirmation never even
// connect.
func TestMonitorAdminClearRefusals(t *testing.T) {
	pipe := func(e *adminEnv) { e.isTerminal = isTerminal }
	cases := []struct {
		name     string
		typed    string
		mutate   func(*adminEnv)
		args     []string
		want     int
		connects bool
		stderr   string
	}{
		{"no terminal", "root\n", pipe, clearArgs, 1, false, "needs a terminal"},
		{"not root", "root\n", func(e *adminEnv) { e.euid = 1000 }, clearArgs, 1, false, "must be run by root"},
		{"free-text reason", "root\n", nil, replaceArg(clearArgs, "false_positive", "the user said so"), 2, false, "-reason must be one of"},
		{"no reason", "root\n", nil, clearArgs[:len(clearArgs)-2], 2, false, "-reason must be one of"},
		{"bad host", "root\n", nil, replaceArg(clearArgs, "claude_code", "copilot"), 2, false, "-host"},
		{"bad uid", "root\n", nil, replaceArg(clearArgs, "1000", "alice"), 2, false, "-uid"},
		{"socket not root's", "root\n", func(e *adminEnv) { e.socketOwner = os.Getuid() + 1 }, clearArgs, 1, false, "refusing the administrative socket"},
		{"nothing typed", "", nil, clearArgs, 1, true, "not typed back"},
		{"yes typed", "yes\n", nil, clearArgs, 1, true, "not typed back"},
		{"another lineage typed", "child\n", nil, clearArgs, 1, true, "not typed back"},
		{"lineage typed with extra", "root \n", nil, clearArgs, 1, true, "not typed back"},
		{"a subagent session named", "child\n", nil, replaceArg(clearArgs, "root", "child"), 1, true, "is a session of lineage root"},
		{"another uid", "root\n", nil, replaceArg(clearArgs, "1000", "1001"), 1, true, "no lineage root for uid 1001"},
		{"another host", "root\n", nil, replaceArg(clearArgs, "claude_code", "opencode"), 1, true, "no lineage root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeAdmin(t)
			r := runAdmin(t, f, tc.typed, tc.mutate, tc.args...)
			if r.code != tc.want || !strings.Contains(r.stderr, tc.stderr) {
				t.Errorf("exit %d, stderr %q; want exit %d with %q", r.code, r.stderr, tc.want, tc.stderr)
			}
			paths, clears := f.seen()
			if len(clears) != 0 {
				t.Errorf("a clear was sent: %+v", clears)
			}
			if connected := len(paths) > 0; connected != tc.connects {
				t.Errorf("connected %v (%v), want %v", connected, paths, tc.connects)
			}
		})
	}
}

func replaceArg(args []string, old, new string) []string {
	out := append([]string(nil), args...)
	for i, a := range out {
		if a == old {
			out[i] = new
			return out
		}
	}
	panic("no " + old)
}

func TestMonitorAdminClearMismatch(t *testing.T) {
	f := newFakeAdmin(t)
	f.answer = admin.CodeMismatch
	r := runAdmin(t, f, "root\n", nil, clearArgs...)
	if r.code != 1 || !strings.Contains(r.stderr, "changed after it was shown; nothing was cleared") {
		t.Errorf("exit %d: %s", r.code, r.stderr)
	}
}

func TestMonitorAdminList(t *testing.T) {
	f := newFakeAdmin(t)
	r := runAdmin(t, f, "", func(e *adminEnv) { e.isTerminal = isTerminal }, "list")
	if r.code != 0 || !strings.Contains(r.stdout, "root") || !strings.Contains(r.stdout, "fetch (2027-01-15T08:00:00Z)") {
		t.Errorf("list: exit %d\n%s%s", r.code, r.stdout, r.stderr)
	}
	r = runAdmin(t, f, "", func(e *adminEnv) { e.euid = 1000 }, "list")
	if r.code != 1 {
		t.Errorf("list as non-root: exit %d", r.code)
	}
	r = runAdmin(t, f, "", nil, "list", "-json")
	var resp admin.ListResponse
	if r.code != 0 || admin.Decode([]byte(r.stdout), admin.MaxResponseBytes, &resp) != nil || len(resp.Lineages) != 1 {
		t.Errorf("list -json: exit %d\n%s", r.code, r.stdout)
	}
}
