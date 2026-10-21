//go:build linux

package jevproxy

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// asOwnUID points geteuid, wantServiceUID and wantKeyUID at the test
// process's own uid, so a deployment it lays out for itself passes the
// ownership checks that, in production, require root (uid 0). The checks
// themselves are exercised unconditionally: only which uid they require is
// swapped in for the test.
func asOwnUID(t *testing.T) {
	t.Helper()
	uid := os.Getuid()
	oldGeteuid, oldService, oldKey := geteuid, wantServiceUID, wantKeyUID
	geteuid = func() int { return uid }
	wantServiceUID = uid
	wantKeyUID = uid
	t.Cleanup(func() {
		geteuid = oldGeteuid
		wantServiceUID = oldService
		wantKeyUID = oldKey
	})
}

// deployment lays out a root-managed deployment's directories and key file
// for the current user, under a short path that fits a socket address, and
// a caller group the current user is a member of (its own primary group).
func deployment(t *testing.T) Config {
	t.Helper()
	asOwnUID(t)
	base, err := os.MkdirTemp("", "jp")
	if err == nil && len(base) > 40 {
		os.RemoveAll(base)
		base, err = os.MkdirTemp("/tmp", "jp")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })

	run := filepath.Join(base, "run")
	if err := os.Mkdir(run, 0o750); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(base, "jev-openrouter.key")
	if err := os.WriteFile(keyPath, []byte("sk-or-v1-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	g, err := user.LookupGroupId(strconv.Itoa(os.Getgid()))
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		Socket:      filepath.Join(run, "jevproxy.sock"),
		KeyPath:     keyPath,
		CallerGroup: g.Name,
		Upstream:    DefaultUpstream,
	}
}

func TestStartChecksDeployment(t *testing.T) {
	cases := map[string]func(t *testing.T, cfg *Config){
		"missing runtime dir": func(t *testing.T, cfg *Config) {
			cfg.Socket = filepath.Join(filepath.Dir(cfg.Socket), "absent", "p.sock")
		},
		"group-writable runtime dir": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(cfg.Socket), 0o770)
		},
		"world-readable runtime dir": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(cfg.Socket), 0o755)
		},
		"group-writable parent": func(t *testing.T, cfg *Config) {
			os.Chmod(filepath.Dir(filepath.Dir(cfg.Socket)), 0o770)
		},
		"symlinked runtime dir": func(t *testing.T, cfg *Config) {
			real := filepath.Dir(cfg.Socket) + "-real"
			os.Rename(filepath.Dir(cfg.Socket), real)
			os.Symlink(real, filepath.Dir(cfg.Socket))
		},
		"relative socket": func(t *testing.T, cfg *Config) { cfg.Socket = "jevproxy.sock" },
		"overlong socket": func(t *testing.T, cfg *Config) { cfg.Socket = "/" + strings.Repeat("s", maxSocketPath) },
		"unknown group":   func(t *testing.T, cfg *Config) { cfg.CallerGroup = "barmkin-no-such-group" },
		"relative key path": func(t *testing.T, cfg *Config) {
			cfg.KeyPath = "jev-openrouter.key"
		},
		"missing key": func(t *testing.T, cfg *Config) {
			os.Remove(cfg.KeyPath)
		},
		"group-readable key": func(t *testing.T, cfg *Config) {
			os.Chmod(cfg.KeyPath, 0o640)
		},
		"bad upstream": func(t *testing.T, cfg *Config) {
			cfg.Upstream = "http://openrouter.ai"
		},
		"running as the wrong uid": func(t *testing.T, cfg *Config) {
			geteuid = func() int { return os.Getuid() + 999999 }
		},
		"socket path taken by a file": func(t *testing.T, cfg *Config) {
			os.WriteFile(cfg.Socket, nil, 0o600)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := deployment(t)
			mutate(t, &cfg)
			if p, err := Start(cfg); err == nil {
				p.Close()
				t.Fatal("started")
			}
		})
	}
}

func TestServeOverSocket(t *testing.T) {
	cfg := deployment(t)
	p, err := Start(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	fi, err := os.Lstat(cfg.Socket)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 || fi.Mode().Perm() != 0o660 {
		t.Errorf("socket mode %v, want a 0660 socket", fi.Mode())
	}
	if gid := fi.Sys().(*syscall.Stat_t).Gid; int(gid) != os.Getgid() {
		t.Errorf("socket group %d, want the caller group %d", gid, os.Getgid())
	}

	conn, err := DialPinned(context.Background(), cfg.Socket, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("DialPinned: %v", err)
	}
	conn.Close()

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", cfg.Socket)
			},
		},
	}
	resp, err := client.Get("http://jevproxy" + healthPath)
	if err != nil {
		t.Fatalf("GET %s: %v", healthPath, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", resp.StatusCode)
	}
	var out map[string]string
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &out); err != nil || out["state"] != "ok" {
		t.Errorf("health body = %s", data)
	}
}
