package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// helperEnv makes the test binary run a monitor instead of tests, so a test
// can kill a real monitor process with SIGKILL.
const helperEnv = "BARMKIN_MONITOR_TEST_HELPER"

func TestMain(m *testing.M) {
	if spec := os.Getenv(helperEnv); spec != "" {
		// socket, state directory, client group, and optionally an
		// administrative socket passed by socket activation, served to
		// this uid in place of root.
		var paths []string
		if err := json.Unmarshal([]byte(spec), &paths); err != nil || len(paths) < 3 {
			os.Exit(3)
		}
		cfg := Config{Socket: paths[0], StateDir: paths[1], ClientGroup: paths[2]}
		if len(paths) > 3 {
			cfg.AdminSocket = paths[3]
			adminUID = uint32(os.Getuid())
		}
		mon, err := Start(cfg)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		ctx, stop := context.WithCancel(context.Background())
		go func() {
			sig := make(chan os.Signal, 1)
			signal.Notify(sig, syscall.SIGTERM)
			<-sig
			stop()
		}()
		if err := mon.Serve(ctx); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// deployment lays out a root-managed deployment's directories for the
// current user, under a short path that fits a socket address.
func deployment(t *testing.T) Config {
	t.Helper()
	base, err := os.MkdirTemp("", "bm")
	if err == nil && len(base) > 60 {
		os.RemoveAll(base)
		base, err = os.MkdirTemp("/tmp", "bm")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	for dir, mode := range map[string]os.FileMode{"run": 0o750, "state": 0o700} {
		p := filepath.Join(base, dir)
		if err := os.Mkdir(p, 0o700); err != nil {
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
	return Config{
		Socket:      filepath.Join(base, "run", "monitor.sock"),
		StateDir:    filepath.Join(base, "state"),
		ClientGroup: g.Name,
	}
}

type running struct {
	m    *Monitor
	stop context.CancelFunc
	done chan error
}

func serve(t *testing.T, cfg Config) *running {
	t.Helper()
	m, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return serveStarted(t, m)
}

func serveStarted(t *testing.T, m *Monitor) *running {
	t.Helper()
	ctx, stop := context.WithCancel(context.Background())
	r := &running{m: m, stop: stop, done: make(chan error, 1)}
	go func() { r.done <- m.Serve(ctx) }()
	t.Cleanup(func() { r.shutdown(t) })
	return r
}

func (r *running) shutdown(t *testing.T) {
	t.Helper()
	if r.stop == nil {
		return
	}
	r.stop()
	r.stop = nil
	if err := <-r.done; err != nil {
		t.Errorf("serve: %v", err)
	}
}

type client struct{ hc *http.Client }

func newClient(socket string) *client {
	uid := uint32(os.Getuid())
	return &client{hc: &http.Client{
		Timeout: proto.ClientDeadline,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return DialPinned(ctx, socket, uid)
			},
		},
	}}
}

func (c *client) do(op proto.Op, body string) (int, []byte, error) {
	resp, err := c.hc.Post("http://monitor"+op.Path(), "application/json", strings.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	return resp.StatusCode, out, err
}

func (c *client) must(t *testing.T, op proto.Op, body string) []byte {
	t.Helper()
	status, out, err := c.do(op, body)
	if err != nil || status != http.StatusOK {
		t.Fatalf("%s: %d %s %v", op, status, out, err)
	}
	return out
}

func registerBody(session string, fresh bool) string {
	return fmt.Sprintf(`{"version":1,"host":"claude_code","session":%q,"root":%q,"fresh":%v,"posture":{"sandbox_enabled":true,"allow_all_unix_sockets":false}}`, session, session, fresh)
}

func observeBody(session string, source proto.Source) string {
	return fmt.Sprintf(`{"version":1,"host":"claude_code","session":%q,"source":%q}`, session, source)
}

func statusBody(session string) string {
	return fmt.Sprintf(`{"version":1,"host":"claude_code","session":%q}`, session)
}

// legsAt returns a session's legs, or the error code status answered.
func (c *client) legsAt(t *testing.T, session string) (proto.Legs, proto.Code) {
	t.Helper()
	status, out, err := c.do(proto.OpStatus, statusBody(session))
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if status != http.StatusOK {
		var e proto.ErrorResponse
		if err := proto.Decode(out, &e); err != nil {
			t.Fatalf("status: %d %s", status, out)
		}
		return proto.Legs{}, e.Error
	}
	var resp proto.StatusResponse
	if err := proto.Decode(out, &resp); err != nil {
		t.Fatalf("status: %s", out)
	}
	return resp.Legs, ""
}

func TestStartChecksDeployment(t *testing.T) {
	cases := map[string]func(t *testing.T, cfg *Config){
		"missing state dir": func(t *testing.T, cfg *Config) { os.Remove(cfg.StateDir) },
		"missing runtime dir": func(t *testing.T, cfg *Config) {
			cfg.Socket = filepath.Join(filepath.Dir(cfg.Socket), "absent", "m.sock")
		},
		"group-readable state dir": func(t *testing.T, cfg *Config) { os.Chmod(cfg.StateDir, 0o750) },
		"group-writable runtime dir": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(cfg.Socket), 0o770)
		},
		"world-readable runtime dir": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(cfg.Socket), 0o755)
		},
		"group-writable parent": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(cfg.StateDir), 0o770)
		},
		"symlinked state dir": func(t *testing.T, cfg *Config) {
			real := cfg.StateDir + "-real"
			os.Rename(cfg.StateDir, real)
			os.Symlink(real, cfg.StateDir)
		},
		"relative socket":   func(t *testing.T, cfg *Config) { cfg.Socket = "monitor.sock" },
		"overlong socket":   func(t *testing.T, cfg *Config) { cfg.Socket = "/" + strings.Repeat("s", maxSocketPath) },
		"unknown group":     func(t *testing.T, cfg *Config) { cfg.ClientGroup = "barmkin-no-such-group" },
		"zero-lifetime ttl": func(t *testing.T, cfg *Config) { cfg.PreregisterTTL = time.Microsecond },
		"running as root": func(t *testing.T, cfg *Config) {
			geteuid = func() int { return 0 }
			t.Cleanup(func() { geteuid = os.Geteuid })
		},
		"journal is a directory": func(t *testing.T, cfg *Config) {
			os.Mkdir(filepath.Join(cfg.StateDir, "journal"), 0o700)
		},
		"socket path taken by a file": func(t *testing.T, cfg *Config) {
			os.WriteFile(cfg.Socket, nil, 0o600)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := deployment(t)
			mutate(t, &cfg)
			if m, err := Start(cfg); err == nil {
				m.Close()
				t.Fatal("started")
			}
		})
	}
}

func TestServeOverSocket(t *testing.T) {
	cfg := deployment(t)
	r := serve(t, cfg)

	fi, err := os.Lstat(cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v, want a 0660 socket", fi.Mode())
	}
	if gid := fi.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getgid() {
		t.Errorf("socket group %d, want the client group %d", gid, os.Getgid())
	}
	for _, name := range []string{"journal", "monitor.lock"} {
		fi, err := os.Stat(filepath.Join(cfg.StateDir, name))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v (%v), want 0600", name, fi.Mode(), err)
		}
	}

	c := newClient(cfg.Socket)
	if out := c.must(t, proto.OpHealth, `{"version":1}`); !bytes.Equal(out, []byte(`{"version":1,"state":"ok"}`)) {
		t.Errorf("health: %s", out)
	}
	c.must(t, proto.OpRegister, registerBody("s1", true))
	c.must(t, proto.OpObserve, observeBody("s1", proto.SourceMCP))
	status, out, _ := c.do(proto.OpDecide, `{"version":1,"host":"claude_code","session":"s1","classes":["net-client"]}`)
	if status != http.StatusOK || !bytes.Contains(out, []byte(`"verdict":"deny"`)) {
		t.Errorf("decide in a tainted session: %d %s", status, out)
	}

	if _, err := DialPinned(context.Background(), cfg.Socket, uint32(os.Getuid())+1); err == nil {
		t.Error("DialPinned accepted a monitor running as another uid")
	}
	if m, err := Start(cfg); err == nil {
		m.Close()
		t.Error("a second monitor started on the same state directory")
	}

	r.shutdown(t)
	if _, err := os.Lstat(cfg.Socket); !os.IsNotExist(err) {
		t.Errorf("socket left behind after a clean stop: %v", err)
	}
	res, err := journal.Load(filepath.Join(cfg.StateDir, "journal"))
	if err != nil || !res.Clean {
		t.Errorf("journal after a clean stop: %+v %v", res, err)
	}
}

func TestCleanRestartKeepsLegs(t *testing.T) {
	cfg := deployment(t)
	r := serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("tainted", true))
	c.must(t, proto.OpObserve, observeBody("tainted", proto.SourceFetch))
	c.must(t, proto.OpRegister, registerBody("clean", true))
	r.shutdown(t)

	serve(t, cfg)
	if legs, code := c.legsAt(t, "tainted"); legs != legsOf(proto.SourceFetch, proto.SourceNone) {
		t.Errorf("tainted after a clean restart: %+v %s", legs, code)
	}
	if legs, code := c.legsAt(t, "clean"); legs != clean {
		t.Errorf("clean after a clean restart: %+v %s", legs, code)
	}
}

func TestDeletedJournalDenies(t *testing.T) {
	cfg := deployment(t)
	r := serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceRead))
	r.shutdown(t)
	if err := os.Remove(filepath.Join(cfg.StateDir, "journal")); err != nil {
		t.Fatal(err)
	}

	serve(t, cfg)
	if _, code := c.legsAt(t, "s"); code != proto.CodeUnknownSession {
		t.Fatalf("a session from a deleted journal: %q, want unknown_session", code)
	}
	var resp proto.RegisterResponse
	if err := proto.Decode(c.must(t, proto.OpRegister, registerBody("s", false)), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Legs.Untrusted != proto.SourceUnknownSession {
		t.Errorf("resuming after a deleted journal: %+v", resp.Legs)
	}
}

func TestDamagedJournalIsSalvaged(t *testing.T) {
	cfg := deployment(t)
	r := serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("kept", true))
	c.must(t, proto.OpObserve, observeBody("kept", proto.SourceCredential))
	c.must(t, proto.OpRegister, registerBody("lost", true))
	r.shutdown(t)

	path := filepath.Join(cfg.StateDir, "journal")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	i := bytes.Index(data, []byte(`"session":"lost"`))
	if i < 0 {
		t.Fatalf("no register record for lost in %s", data)
	}
	data[i+12] ^= 0x01
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	serve(t, cfg)
	if aside, _ := filepath.Glob(path + ".damaged-*"); len(aside) != 1 {
		t.Errorf("damaged journal not moved aside: %v", aside)
	}
	if legs, code := c.legsAt(t, "kept"); legs != legsOf(proto.SourceMonitorRestart, proto.SourceCredential) {
		t.Errorf("a session that survived the damage: %+v %s", legs, code)
	}
	if _, code := c.legsAt(t, "lost"); code != proto.CodeUnknownSession {
		t.Errorf("a session whose record was damaged: %q, want unknown_session", code)
	}
}

func TestOversizedJournalIsQuarantined(t *testing.T) {
	cfg := deployment(t)
	path := filepath.Join(cfg.StateDir, "journal")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(journal.MaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	serve(t, cfg)
	if aside, _ := filepath.Glob(path + ".damaged-*"); len(aside) != 1 {
		t.Errorf("journal not moved aside: %v", aside)
	}
	c := newClient(cfg.Socket)
	if _, code := c.legsAt(t, "s"); code != proto.CodeUnknownSession {
		t.Errorf("a session after an unreadable journal: %q, want unknown_session", code)
	}
	if _, err := journal.Load(path); err != nil {
		t.Errorf("replacement journal unreadable: %v", err)
	}
}

func TestUnsafeJournalIsRefusedUntouched(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"group-readable": func(t *testing.T, path string) {
			os.WriteFile(path, nil, 0o600)
			os.Chmod(path, 0o640)
		},
		"symlink": func(t *testing.T, path string) {
			os.Symlink(path+"-target", path)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := deployment(t)
			path := filepath.Join(cfg.StateDir, "journal")
			setup(t, path)
			before, _ := os.Lstat(path)
			if m, err := Start(cfg); err == nil {
				m.Close()
				t.Fatal("started")
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Errorf("journal path was changed: %v", err)
			}
			if aside, _ := filepath.Glob(path + ".damaged-*"); len(aside) != 0 {
				t.Errorf("unsafe journal moved aside: %v", aside)
			}
		})
	}
}

// A real monitor process killed with SIGKILL keeps every acknowledged leg,
// and marks every lineage it knew with monitor_restart.
func TestKill9(t *testing.T) {
	cfg := deployment(t)
	spec, err := json.Marshal([]string{cfg.Socket, cfg.StateDir, cfg.ClientGroup})
	if err != nil {
		t.Fatal(err)
	}
	start := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), helperEnv+"="+string(spec))
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		c := newClient(cfg.Socket)
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
			if status, _, err := c.do(proto.OpHealth, `{"version":1}`); err == nil && status == http.StatusOK {
				return cmd
			}
			if time.Now().After(deadline) {
				cmd.Process.Kill()
				t.Fatal("monitor did not come up")
			}
		}
	}

	cmd := start()
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("tainted", true))
	c.must(t, proto.OpObserve, observeBody("tainted", proto.SourceMCP))
	c.must(t, proto.OpRegister, registerBody("clean", true))
	cmd.Process.Signal(syscall.SIGKILL)
	cmd.Wait()

	cmd = start()
	if legs, code := c.legsAt(t, "tainted"); legs != legsOf(proto.SourceMCP, proto.SourceNone) {
		t.Errorf("tainted after kill -9: %+v %s", legs, code)
	}
	if legs, code := c.legsAt(t, "clean"); legs != legsOf(proto.SourceMonitorRestart, proto.SourceNone) {
		t.Errorf("clean after kill -9: %+v %s", legs, code)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if err := cmd.Wait(); err != nil {
		t.Errorf("monitor exit after SIGTERM: %v", err)
	}
	if res, err := journal.Load(filepath.Join(cfg.StateDir, "journal")); err != nil || !res.Clean {
		t.Errorf("journal after SIGTERM: %+v %v", res, err)
	}
}
