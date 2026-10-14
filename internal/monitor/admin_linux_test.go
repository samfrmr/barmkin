package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/admin"
	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// adminDeployment is a deployment with an administrative socket in its own
// 0700 directory, bound by the test in place of systemd.
func adminDeployment(t *testing.T) Config {
	t.Helper()
	cfg := deployment(t)
	dir := filepath.Join(filepath.Dir(filepath.Dir(cfg.Socket)), "admin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg.AdminSocket = filepath.Join(dir, "admin.sock")
	listenAdmin = func(path string) (net.Listener, error) {
		os.Remove(path) // the last run's, left in place as systemd leaves its socket
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, err
		}
		ln.(*net.UnixListener).SetUnlinkOnClose(false) // as systemd's socket, the path outlives the monitor
		return ln, nil
	}
	t.Cleanup(func() { listenAdmin = inheritedSocket })
	return cfg
}

// asAdmin makes this test's uid the administrative uid, in place of root.
func asAdmin(t *testing.T) {
	adminUID = uint32(os.Getuid())
	t.Cleanup(func() { adminUID = 0 })
}

func (c *client) code(t *testing.T, op proto.Op, body string) proto.Code {
	t.Helper()
	status, out, err := c.do(op, body)
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	if status == http.StatusOK {
		return ""
	}
	var e proto.ErrorResponse
	if err := proto.Decode(out, &e); err != nil {
		t.Fatalf("%s: %d %s", op, status, out)
	}
	return e.Error
}

func gateBody(session, id string) string {
	return `{"version":1,"host":"claude_code","session":"` + session + `","call":"` + id + `"}`
}

// An ordinary user, a plugin or an MCP server running as that user never
// gets an answer from the administrative socket: the monitor drops the
// connection before reading the request.
func TestAdminSocketDropsNonRoot(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("runs as root")
	}
	cfg := adminDeployment(t)
	// The directory passes as root's; the peers stay this non-root uid.
	asAdmin(t)
	m, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	adminUID = 0
	serveStarted(t, m)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceFetch))

	ac := admin.NewClient(cfg.AdminSocket)
	if _, err := ac.List(context.Background()); err == nil || errors.As(err, new(*admin.Error)) {
		t.Errorf("list from a non-root peer: %v, want the connection dropped", err)
	}
	_, err = ac.Clear(context.Background(), admin.ClearRequest{UID: uint32(os.Getuid()), Host: proto.HostClaudeCode,
		Lineage: "s", Legs: legsOf(proto.SourceFetch, proto.SourceNone), Reason: journal.ReasonFalsePositive})
	if err == nil || errors.As(err, new(*admin.Error)) {
		t.Errorf("clear from a non-root peer: %v, want the connection dropped", err)
	}

	conn, err := net.Dial("unix", cfg.AdminSocket)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	conn.Write([]byte("POST /admin/v1/list HTTP/1.1\r\nHost: x\r\nContent-Length: 13\r\n\r\n{\"version\":1}"))
	if n, err := conn.Read(make([]byte, 64)); n != 0 || err == nil {
		t.Errorf("a non-root peer read %d bytes (%v) from the administrative socket", n, err)
	}
	conn.Close()

	if legs, code := c.legsAt(t, "s"); legs != legsOf(proto.SourceFetch, proto.SourceNone) {
		t.Errorf("legs after non-root administrative requests: %+v %s", legs, code)
	}
}

// The client socket answers no administrative path, from any peer.
func TestClientSocketRefusesAdminPaths(t *testing.T) {
	cfg := adminDeployment(t)
	asAdmin(t)
	serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceMCP))
	body := `{"version":1,"uid":` + itoa(os.Getuid()) + `,"host":"claude_code","lineage":"s","epoch":0,"legs":{"untrusted":"mcp","sensitive":"none"},"reason":"false_positive"}`
	for _, op := range admin.Ops {
		resp, err := c.hc.Post("http://monitor"+op.Path(), "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s on the client socket: %d, want 400", op, resp.StatusCode)
		}
	}
	if legs, code := c.legsAt(t, "s"); legs != legsOf(proto.SourceMCP, proto.SourceNone) {
		t.Errorf("legs after administrative paths on the client socket: %+v %s", legs, code)
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

// Root's clear over the socket is on disk before it is answered, forces
// every session to register again, and survives a clean restart with the
// cleared legs still in the history.
func TestAdminSocketClear(t *testing.T) {
	cfg := adminDeployment(t)
	asAdmin(t)
	r := serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceFetch))
	c.must(t, proto.OpPreregister, gateBody("s", "toolu_before"))

	ac := admin.NewClient(cfg.AdminSocket)
	list, err := ac.List(context.Background())
	if err != nil || len(list.Lineages) != 1 {
		t.Fatalf("list: %+v %v", list, err)
	}
	l := list.Lineages[0]
	resp, err := ac.Clear(context.Background(), admin.ClearRequest{UID: l.UID, Host: l.Host, Lineage: l.Lineage,
		Epoch: l.Epoch, Legs: l.Legs, Reason: journal.ReasonFalsePositive})
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if resp.Lineage.Legs != clean || resp.Lineage.Epoch != 1 {
		t.Errorf("clear answered %+v", resp.Lineage)
	}

	// The clear was fsynced before the answer: it is already in the file.
	res, err := journal.Load(filepath.Join(cfg.StateDir, "journal"))
	if err != nil {
		t.Fatal(err)
	}
	last := res.Records[len(res.Records)-1]
	if last.Kind != journal.KindClear || last.Root != "s" || last.Epoch != 1 || last.Reason != journal.ReasonFalsePositive {
		t.Errorf("last journal record after an answered clear: %+v", last)
	}

	if _, err := ac.Clear(context.Background(), admin.ClearRequest{UID: l.UID, Host: l.Host, Lineage: l.Lineage,
		Epoch: l.Epoch, Legs: l.Legs, Reason: journal.ReasonFalsePositive}); !isAdminCode(err, admin.CodeMismatch) {
		t.Errorf("a replayed clear: %v, want mismatch", err)
	}

	if code := c.code(t, proto.OpGate, gateBody("s", "toolu_before")); code != proto.CodeUnknownSession {
		t.Errorf("gate before registering again: %q, want unknown_session", code)
	}
	var reg proto.RegisterResponse
	if err := proto.Decode(c.must(t, proto.OpRegister, registerBody("s", false)), &reg); err != nil || reg.Legs != clean {
		t.Errorf("register again: %+v %v", reg.Legs, err)
	}
	var gate proto.GateResponse
	if err := proto.Decode(c.must(t, proto.OpGate, gateBody("s", "toolu_before")), &gate); err != nil || gate.Preregistered {
		t.Errorf("a pre-registration from before the clear: %+v %v", gate, err)
	}

	r.shutdown(t)
	serve(t, cfg)
	if legs, code := c.legsAt(t, "s"); legs != clean {
		t.Errorf("after a clean restart: %+v %s", legs, code)
	}
	list, err = admin.NewClient(cfg.AdminSocket).List(context.Background())
	if err != nil || len(list.Lineages) != 1 || len(list.Lineages[0].Clears) != 1 ||
		list.Lineages[0].Clears[0].Legs != legsOf(proto.SourceFetch, proto.SourceNone) {
		t.Errorf("history after a clean restart: %+v %v", list, err)
	}
}

func isAdminCode(err error, code admin.Code) bool {
	ae, ok := errors.AsType[*admin.Error](err)
	return ok && ae.Code == code
}

func TestStartChecksAdminSocket(t *testing.T) {
	cases := map[string]func(t *testing.T, cfg *Config){
		"no socket passed by systemd": func(t *testing.T, cfg *Config) {
			listenAdmin = inheritedSocket
			asAdmin(t)
		},
		"directory not root's": func(t *testing.T, cfg *Config) {
			if os.Getuid() == 0 {
				t.Skip("runs as root")
			}
		},
		"group-readable directory": func(t *testing.T, cfg *Config) {
			asAdmin(t)
			os.Chmod(filepath.Dir(cfg.AdminSocket), 0o750)
		},
		"missing directory": func(t *testing.T, cfg *Config) {
			asAdmin(t)
			cfg.AdminSocket = filepath.Join(filepath.Dir(cfg.AdminSocket), "absent", "admin.sock")
		},
		"symlinked directory": func(t *testing.T, cfg *Config) {
			asAdmin(t)
			dir := filepath.Dir(cfg.AdminSocket)
			os.Rename(dir, dir+"-real")
			os.Symlink(dir+"-real", dir)
		},
		"relative path": func(t *testing.T, cfg *Config) {
			asAdmin(t)
			cfg.AdminSocket = "admin.sock"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := adminDeployment(t)
			mutate(t, &cfg)
			if m, err := Start(cfg); err == nil {
				m.Close()
				t.Fatal("started")
			}
			if _, err := os.Lstat(cfg.Socket); !os.IsNotExist(err) {
				t.Errorf("a refused start left the client socket: %v", err)
			}
		})
	}
}

// A real monitor process takes the administrative socket systemd passes,
// by the socket activation protocol, and refuses to start without it.
func TestAdminSocketActivation(t *testing.T) {
	cfg := deployment(t)
	dir := filepath.Join(filepath.Dir(filepath.Dir(cfg.Socket)), "admin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "admin.sock")
	spec, err := json.Marshal([]string{cfg.Socket, cfg.StateDir, cfg.ClientGroup, path})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	f, err := ln.(*net.UnixListener).File()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// start runs the monitor as systemd would: the socket on fd 3, and
	// LISTEN_PID set to the monitor's own pid by exec from sh.
	start := func(pid string, env ...string) *exec.Cmd {
		cmd := exec.Command("sh", "-c", `LISTEN_PID=`+pid+` exec "$0" "$@"`, os.Args[0], "-test.run=^$")
		cmd.Env = append(append(os.Environ(), helperEnv+"="+string(spec)), env...)
		cmd.ExtraFiles = []*os.File{f}
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	refused := func(name, pid string, env ...string) {
		t.Helper()
		cmd := start(pid, env...)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if ee, ok := errors.AsType[*exec.ExitError](err); !ok || ee.ExitCode() != 1 {
				t.Errorf("%s: monitor exit %v, want 1", name, err)
			}
		case <-time.After(10 * time.Second):
			cmd.Process.Kill()
			t.Errorf("%s: monitor started", name)
		}
	}
	refused("no LISTEN_FDS", "$$")
	refused("another process's sockets", "1", "LISTEN_FDS=1", "LISTEN_FDNAMES="+AdminFDName)
	refused("a socket of another name", "$$", "LISTEN_FDS=1", "LISTEN_FDNAMES=other")

	cmd := start("$$", "LISTEN_FDS=1", "LISTEN_FDNAMES="+AdminFDName)
	c := newClient(cfg.Socket)
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if status, _, err := c.do(proto.OpHealth, `{"version":1}`); err == nil && status == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatal("monitor did not come up")
		}
	}
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceRead))
	list, err := admin.NewClient(path).List(context.Background())
	if err != nil || len(list.Lineages) != 1 || list.Lineages[0].Legs != legsOf(proto.SourceRead, proto.SourceNone) {
		t.Errorf("list over the inherited socket: %+v %v", list, err)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Errorf("monitor exit after SIGTERM: %v", err)
	}
	if _, err := os.Lstat(path); err != nil {
		t.Errorf("the monitor removed systemd's socket: %v", err)
	}
}
