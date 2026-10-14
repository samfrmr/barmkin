package monitor

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

	"github.com/Daviey/barmkin/internal/journal"
)

// Defaults for the root-managed service deployment.
const (
	DefaultSocket      = "/run/barmkin/monitor.sock"
	DefaultStateDir    = "/var/lib/barmkin"
	DefaultClientGroup = "barmkin-clients"
	// DefaultAdminSocket is where barmkin-monitor-admin.socket puts the
	// opt-in administrative socket, in a directory only root can enter.
	DefaultAdminSocket = "/run/barmkin-admin/admin.sock"
)

// maxSocketPath is the longest socket path bind accepts (sun_path less
// its terminating NUL).
const maxSocketPath = 107

// Config is how a monitor is deployed.
type Config struct {
	Socket         string        // the client socket, in a root-created runtime directory
	StateDir       string        // the root-created state directory holding the journal
	ClientGroup    string        // the group whose members may connect
	PreregisterTTL time.Duration // how long a pre-registration stays live
	// AdminSocket, when set, is the path of the root-owned administrative
	// socket systemd passes to the monitor (internal/admin). It is empty by
	// default: the monitor then has no administrative socket, and nothing
	// lowers a leg.
	AdminSocket string
	Logf        func(format string, args ...any)
}

// Monitor is a started monitor: its state is replayed and journaled, and
// its socket is listening.
type Monitor struct {
	core    *core
	journal *journal.Journal
	lock    *os.File
	ln      net.Listener
	adminLn net.Listener // nil without an administrative socket
	logf    func(format string, args ...any)
}

// geteuid is os.Geteuid, replaceable in tests.
var geteuid = os.Geteuid

// Start checks the deployment, replays and compacts the journal, and
// listens on the socket. It refuses to start, rather than serve with weaker
// guarantees, when any check fails. The caller must Serve or Close the
// monitor.
func Start(cfg Config) (*Monitor, error) {
	logf := cfg.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if cfg.PreregisterTTL == 0 {
		cfg.PreregisterTTL = DefaultPreregisterTTL
	}
	if cfg.PreregisterTTL < time.Millisecond {
		return nil, errors.New("pre-registration lifetime must be at least 1ms")
	}
	euid := geteuid()
	if euid == 0 {
		return nil, errors.New("refusing to run as root: run the monitor as its dedicated service user")
	}
	gid, err := lookupGroup(cfg.ClientGroup)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Socket) || len(cfg.Socket) > maxSocketPath {
		return nil, fmt.Errorf("socket path must be absolute and at most %d bytes", maxSocketPath)
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, errors.New("state directory must be an absolute path")
	}
	// Both directories are created by root (systemd's StateDirectory and
	// RuntimeDirectory) and owned by the service user. Nobody else may
	// write to them, or to any directory above them, so nobody else can
	// replace the journal or the socket.
	if err := checkDir(cfg.StateDir, euid, 0o077); err != nil {
		return nil, fmt.Errorf("state directory: %w", err)
	}
	if err := checkDir(filepath.Dir(cfg.Socket), euid, 0o027); err != nil {
		return nil, fmt.Errorf("runtime directory: %w", err)
	}

	syscall.Umask(0o077)
	m := &Monitor{logf: logf}
	if m.lock, err = lockState(cfg.StateDir); err != nil {
		return nil, err
	}
	if err := m.replay(cfg.StateDir); err != nil {
		m.Close()
		return nil, err
	}
	m.core.ttl = cfg.PreregisterTTL
	if cfg.AdminSocket != "" {
		if m.adminLn, err = startAdmin(cfg.AdminSocket); err != nil {
			m.Close()
			return nil, err
		}
	}
	if m.ln, err = listen(cfg.Socket, gid); err != nil {
		m.Close()
		return nil, fmt.Errorf("listen: %w", err)
	}
	return m, nil
}

// replay loads the journal, rebuilds state from it, and replaces it with a
// compacted snapshot ending in a start record. A damaged journal is moved
// aside first: the sessions it still names are rebuilt from the records
// that survived, and the rest become unknown, so they deny until they
// register again.
func (m *Monitor) replay(stateDir string) error {
	path := filepath.Join(stateDir, "journal")
	res, err := journal.Load(path)
	if errors.Is(err, journal.ErrUnreadable) {
		aside, qerr := moveAside(path)
		if qerr != nil {
			return fmt.Errorf("%w (and could not move it aside: %v)", err, qerr)
		}
		m.logf("journal unreadable (%v); moved it to %s and every session starts unknown", err, aside)
		res = journal.Result{}
	} else if err != nil {
		return err
	} else if res.Damaged {
		aside, err := moveAside(path)
		if err != nil {
			return fmt.Errorf("move damaged journal aside: %w", err)
		}
		m.logf("journal damaged; moved it to %s and kept %d valid records", aside, len(res.Records))
	}
	if stale, _ := filepath.Glob(filepath.Join(stateDir, ".journal-*")); len(stale) > 0 {
		for _, f := range stale {
			os.Remove(f)
		}
	}
	m.core = newCore(res.Records, res.Clean)
	if !res.Clean {
		m.logf("last run did not stop cleanly; every known lineage is marked monitor_restart")
	}
	m.journal, err = journal.Create(path, append(m.core.snapshot(), journal.Record{Kind: journal.KindStart}))
	if err != nil {
		return err
	}
	m.core.journal = m.journal
	m.logf("replayed %d sessions in %d lineages", len(m.core.sessions), len(m.core.lineages))
	return nil
}

// moveAside renames the journal, which must be a regular file, to a unique
// name next to it. Anything else is refused rather than moved.
func moveAside(path string) (string, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	aside := fmt.Sprintf("%s.damaged-%d", path, time.Now().UnixNano())
	if err := os.Rename(path, aside); err != nil {
		return "", err
	}
	return aside, nil
}

// Serve answers requests until ctx is done, then stops accepting, drains
// the requests in flight, journals a clean stop and closes the monitor. With
// an administrative socket it serves that too, on its own server.
func (m *Monitor) Serve(ctx context.Context) error {
	servers := []*http.Server{newServer(m.core)}
	listeners := []net.Listener{peerListener{m.ln}}
	if m.adminLn != nil {
		servers = append(servers, newServer(adminHandler{core: m.core, logf: m.logf}))
		listeners = append(listeners, m.adminLn)
	}
	done := make(chan error, len(servers))
	for i, srv := range servers {
		go func() { done <- srv.Serve(listeners[i]) }()
	}

	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, srv := range servers {
		srv.Shutdown(shutdown)
	}
	if errors.Is(serveErr, http.ErrServerClosed) {
		serveErr = nil
	}
	return errors.Join(serveErr, m.Close())
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if pc, ok := c.(*peerConn); ok {
				return withPeer(ctx, pc.uid)
			}
			return ctx
		},
	}
}

// Close journals a clean stop when the monitor is healthy, and releases
// the socket, the journal and the state lock.
func (m *Monitor) Close() error {
	var errs []error
	if m.ln != nil {
		errs = append(errs, ignoreClosed(m.ln.Close()))
	}
	if m.adminLn != nil {
		errs = append(errs, ignoreClosed(m.adminLn.Close()))
	}
	if m.core != nil && m.core.journal != nil {
		errs = append(errs, m.core.close())
	}
	if m.journal != nil {
		m.journal.Close()
	}
	if m.lock != nil {
		m.lock.Close()
	}
	return errors.Join(errs...)
}

func ignoreClosed(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}

func lookupGroup(name string) (int, error) {
	if name == "" {
		return 0, errors.New("a client group is required")
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("client group: %w", err)
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return 0, fmt.Errorf("client group %s: bad gid %q", name, g.Gid)
	}
	return gid, nil
}

// checkDir requires dir to be an existing directory, not a symlink, owned
// by uid, with none of the forbidden permission bits. Every directory above
// it must be owned by root or uid, and writable by nobody else unless it is
// sticky.
func checkDir(dir string, uid int, forbidden os.FileMode) error {
	dir = filepath.Clean(dir)
	fi, err := os.Lstat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Errorf("%s does not exist; it must be created by root for the service user", dir)
	case err != nil:
		return err
	case !fi.IsDir():
		return fmt.Errorf("%s is not a directory", dir)
	case owner(fi) != uid:
		return fmt.Errorf("%s is not owned by the service user (uid %d)", dir, uid)
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
			return fmt.Errorf("%s is owned by uid %d, not root or the service user", p, owner(fi))
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

// lockState takes the state directory's lock for the life of the process,
// so two monitors can never share one journal or replace each other's
// socket.
func lockState(stateDir string) (*os.File, error) {
	path := filepath.Join(stateDir, "monitor.lock")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open state lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s (is another monitor running?): %w", path, err)
	}
	return f, nil
}

// listen binds the socket, replacing a stale one left by an earlier run,
// and opens it to the client group only: mode 0660, group gid.
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
		return nil, fmt.Errorf("give the socket to the client group (is the service user a member?): %w", err)
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// peerListener accepts only connections whose peer it can identify. A
// connection it cannot is closed before any request is read.
type peerListener struct{ net.Listener }

type peerConn struct {
	net.Conn
	uid uint32
}

func (l peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			conn.Close()
			continue
		}
		uid, err := peerUID(uc)
		if err != nil {
			conn.Close()
			continue
		}
		return &peerConn{Conn: conn, uid: uid}, nil
	}
}

// DialPinned connects to the monitor socket and checks, by the kernel's
// peer credentials, that the process listening on it runs as uid: the
// service user. A Go client uses it so that a process that took over the
// socket path is never mistaken for the monitor.
func DialPinned(ctx context.Context, socket string, uid uint32) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	got, err := peerUID(conn.(*net.UnixConn))
	if err != nil {
		conn.Close()
		return nil, err
	}
	if got != uid {
		conn.Close()
		return nil, fmt.Errorf("monitor socket is served by uid %d, not %d", got, uid)
	}
	return conn, nil
}
