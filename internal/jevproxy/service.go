package jevproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// maxSocketPath is the longest socket path bind accepts (sun_path less its
// terminating NUL).
const maxSocketPath = 107

// geteuid is os.Geteuid, replaceable in tests.
var geteuid = os.Geteuid

// wantServiceUID is the uid the proxy must run as, and the uid that must
// own its runtime directory. It is 0 (root) outside tests: the captain's
// choice is a root-owned central path, so no agent-uid component ever
// holds the OpenRouter key.
var wantServiceUID = 0

// Proxy is a started Jev proxy: its key is loaded and its socket is
// listening.
type Proxy struct {
	cfg  Config
	rt   http.RoundTripper
	key  Secret
	ln   net.Listener
	logf func(format string, args ...any)
}

// Start checks the deployment, loads the key, and listens on the socket.
// It refuses to start, rather than serve with weaker guarantees, when any
// check fails. The caller must Serve or Close the returned Proxy.
func Start(cfg Config) (*Proxy, error) {
	cfg = cfg.withDefaults()
	if geteuid() != wantServiceUID {
		return nil, fmt.Errorf("refusing to run as uid %d: the Jev proxy must run as uid %d so it alone can read its key file", geteuid(), wantServiceUID)
	}
	gid, err := lookupGroup(cfg.CallerGroup)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Socket) || len(cfg.Socket) > maxSocketPath {
		return nil, fmt.Errorf("socket path must be absolute and at most %d bytes", maxSocketPath)
	}
	if !filepath.IsAbs(cfg.KeyPath) {
		return nil, errors.New("key path must be an absolute path")
	}
	// The runtime directory is created by root (systemd's RuntimeDirectory)
	// and owned by the uid this process runs as. Nobody else may write to
	// it, or to any directory above it, so nobody else can replace the
	// socket or race it into existence first.
	if err := checkDir(filepath.Dir(cfg.Socket), wantServiceUID, 0o027); err != nil {
		return nil, fmt.Errorf("runtime directory: %w", err)
	}
	rt, err := newUpstreamTransport(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream: %w", err)
	}
	key, err := LoadKey(cfg.KeyPath)
	if err != nil {
		return nil, err
	}
	ln, err := listen(cfg.Socket, gid)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	return &Proxy{cfg: cfg, rt: rt, key: key, ln: ln, logf: cfg.Logf}, nil
}

// Serve answers requests until ctx is done, then stops accepting, drains
// requests in flight, and closes the proxy.
func (p *Proxy) Serve(ctx context.Context) error {
	srv := &http.Server{
		Handler:           p.handler(),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       p.cfg.Timeout,
		WriteTimeout:      p.cfg.Timeout + 2*time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(p.ln) }()

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	srv.Shutdown(shutdown)
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, p.Close())
}

// Close releases the socket. It is safe to call more than once.
func (p *Proxy) Close() error {
	if p.ln == nil {
		return nil
	}
	err := p.ln.Close()
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func lookupGroup(name string) (int, error) {
	if name == "" {
		return 0, errors.New("a caller group is required")
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("caller group: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("caller group %s: bad gid %q", name, g.Gid)
	}
	return gid, nil
}

// checkDir requires dir to be an existing directory, not a symlink, owned
// by uid, with none of the forbidden permission bits. Every directory
// above it must be owned by root or uid, and writable by nobody else
// unless it is sticky.
func checkDir(dir string, uid int, forbidden os.FileMode) error {
	dir = filepath.Clean(dir)
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s does not exist; it must be created by root for this service", dir)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case owner(fi) != uid:
		return fmt.Errorf("%s is not owned by uid %d", dir, uid)
	case fi.Mode().Perm()&forbidden != 0:
		return fmt.Errorf("%s has mode %#o; it must allow none of %#o", dir, fi.Mode().Perm(), forbidden)
	}
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := fi.Mode()
		switch {
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case owner(fi) != 0 && owner(fi) != uid:
			return fmt.Errorf("%s is owned by uid %d, not root or uid %d", p, owner(fi), uid)
		case mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0:
			return fmt.Errorf("%s is writable by group or other", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func owner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// listen binds the socket, replacing a stale one left by an earlier run,
// and opens it to the caller group only: mode 0660, group gid. A caller
// authenticates only by reaching this socket; it presents no credential.
func listen(path string, gid int) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chown(path, -1, gid); err != nil {
		ln.Close()
		return nil, fmt.Errorf("give the socket to the caller group: %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}
