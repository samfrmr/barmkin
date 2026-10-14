package monitor

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Daviey/barmkin/internal/admin"
	"github.com/Daviey/barmkin/internal/journal"
)

// adminUID is the only uid the administrative socket serves, and the owner
// its directory must have: root. Tests replace it.
var adminUID uint32 = 0

// AdminFDName is the name systemd gives the administrative socket it
// passes (FileDescriptorName= in barmkin-monitor-admin.socket).
const AdminFDName = "barmkin-admin"

// listenAdmin returns the administrative socket at path. Tests replace it.
var listenAdmin = inheritedSocket

// inheritedSocket returns the listening Unix socket at path that systemd
// passed by socket activation (LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES). The
// monitor never creates the administrative socket itself: it runs as its
// service user, and the socket must be root's.
func inheritedSocket(path string) (net.Listener, error) {
	pid, fds, names := os.Getenv("LISTEN_PID"), os.Getenv("LISTEN_FDS"), os.Getenv("LISTEN_FDNAMES")
	for _, k := range []string{"LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"} {
		os.Unsetenv(k)
	}
	n, err := strconv.Atoi(fds)
	if pid != strconv.Itoa(os.Getpid()) || err != nil || n < 1 {
		return nil, fmt.Errorf("no socket was passed for %s: the administrative socket is root's, and systemd passes it (barmkin-monitor-admin.socket)", path)
	}
	named := strings.Split(names, ":")
	var found net.Listener
	for i := range n {
		f := os.NewFile(uintptr(3+i), "listen-fd-"+strconv.Itoa(i))
		ln, err := net.FileListener(f)
		f.Close()
		if err != nil {
			continue
		}
		ul, ok := ln.(*net.UnixListener)
		nameOK := names == "" || (i < len(named) && named[i] == AdminFDName)
		if found == nil && ok && nameOK && ul.Addr().String() == path {
			ul.SetUnlinkOnClose(false) // systemd owns the path
			found = ul
			continue
		}
		ln.Close()
	}
	if found == nil {
		return nil, fmt.Errorf("systemd passed no listening Unix socket named %s at %s", AdminFDName, path)
	}
	return found, nil
}

// startAdmin checks the administrative socket's directory and takes the
// socket. The directory must be root's and closed to everyone else, so
// only root can reach the socket at all; the listener then drops every
// connection whose peer is not root.
func startAdmin(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || len(path) > maxSocketPath {
		return nil, fmt.Errorf("administrative socket path must be absolute and at most %d bytes", maxSocketPath)
	}
	if err := checkDir(filepath.Dir(path), int(adminUID), 0o077); err != nil {
		return nil, fmt.Errorf("administrative socket directory: %w", err)
	}
	ln, err := listenAdmin(path)
	if err != nil {
		return nil, err
	}
	return adminListener{ln}, nil
}

// adminListener accepts only connections from adminUID, and closes every
// other connection before a byte of it is read.
type adminListener struct{ net.Listener }

func (l adminListener) Accept() (net.Conn, error) {
	for {
		conn, err := peerListener(l).Accept()
		if err != nil {
			return nil, err
		}
		if conn.(*peerConn).uid != adminUID {
			conn.Close()
			continue
		}
		return conn, nil
	}
}

// adminHandler answers the administrative contract (internal/admin).
type adminHandler struct {
	core *core
	logf func(format string, args ...any)
}

func (h adminHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if uid, ok := peerFrom(r.Context()); !ok || uid != adminUID {
		writeAdminError(w, admin.CodeForbidden)
		return
	}
	op, ok := admin.ParsePath(r.URL.Path)
	if !ok || r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeAdminError(w, admin.CodeBadRequest)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, admin.MaxRequestBytes+1))
	if err != nil {
		writeAdminError(w, admin.CodeBadRequest)
		return
	}
	req := admin.NewRequest(op)
	if err := admin.Decode(body, admin.MaxRequestBytes, req); err != nil {
		writeAdminError(w, admin.CodeBadRequest)
		return
	}
	var resp admin.Message
	switch req := req.(type) {
	case *admin.ListRequest:
		resp = h.core.adminList()
	case *admin.ClearRequest:
		resp, err = h.core.adminClear(req)
		if err == nil {
			h.logf("root cleared lineage %s of uid %d on %s, starting epoch %d (%s)", req.Lineage, req.UID, req.Host, req.Epoch+1, req.Reason)
		}
	}
	if err != nil {
		code := admin.CodeUnavailable
		if ae, ok := errors.AsType[*admin.Error](err); ok {
			code = ae.Code
		}
		writeAdminError(w, code)
		return
	}
	out, err := admin.Encode(resp)
	if err != nil {
		writeAdminError(w, admin.CodeUnavailable)
		return
	}
	write(w, http.StatusOK, out)
}

func writeAdminError(w http.ResponseWriter, code admin.Code) {
	out, _ := admin.Encode(&admin.ErrorResponse{Version: admin.Version, Error: code})
	write(w, code.HTTPStatus(), out)
}

func adminFail(code admin.Code) error { return &admin.Error{Code: code} }

// adminList lists every lineage, its sessions and its cleared history.
func (c *core) adminList() *admin.ListResponse {
	c.mu.Lock()
	defer c.mu.Unlock()
	sessions := map[lineageKey][]admin.Session{}
	for sk, s := range c.sessions {
		lk := lineageKey{sk.uid, sk.host, s.root}
		sessions[lk] = append(sessions[lk], admin.Session{Session: sk.session, Current: s.epoch == c.lineage(lk).epoch, At: s.at})
	}
	resp := &admin.ListResponse{Version: admin.Version, Lineages: []admin.Lineage{}}
	for _, lk := range c.lineageKeys() {
		ss := sessions[lk]
		slices.SortFunc(ss, func(a, b admin.Session) int { return strings.Compare(a.Session, b.Session) })
		resp.Lineages = append(resp.Lineages, c.view(lk, ss))
	}
	return resp
}

// view is lk's state as the administrative contract shows it.
func (c *core) view(lk lineageKey, sessions []admin.Session) admin.Lineage {
	l := c.lineage(lk)
	if sessions == nil {
		sessions = []admin.Session{}
	}
	v := admin.Lineage{
		UID: lk.uid, Host: lk.host, Lineage: lk.root, Epoch: l.epoch,
		Legs: l.legs, UntrustedAt: l.untrustedAt, SensitiveAt: l.sensitiveAt,
		Sessions: sessions, Clears: []admin.Clear{},
	}
	cl := admin.Clear{Legs: cleanLegs}
	for _, r := range l.history {
		switch {
		case r.Kind == journal.KindRaise && r.Leg == journal.LegUntrusted:
			cl.Legs.Untrusted, cl.UntrustedAt = r.Source, r.At
		case r.Kind == journal.KindRaise:
			cl.Legs.Sensitive, cl.SensitiveAt = r.Source, r.At
		case r.Kind == journal.KindClear:
			cl.Epoch, cl.Reason, cl.At = r.Epoch, r.Reason, r.At
			v.Clears = append(v.Clears, cl)
			cl = admin.Clear{Legs: cleanLegs}
		}
	}
	return v
}

// adminClear clears one lineage: it journals a clear record starting the
// lineage's next epoch and, only once that is durable, lowers both legs,
// keeps what they held in the lineage's history and drops the lineage's
// pre-registrations. Every session of the lineage must then register again.
// The lineage must be named exactly, with the epoch and legs the operator
// was shown.
func (c *core) adminClear(req *admin.ClearRequest) (*admin.ClearResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.degraded {
		return nil, adminFail(admin.CodeUnavailable)
	}
	lk := lineageKey{req.UID, req.Host, req.Lineage}
	l, ok := c.lineages[lk]
	if !ok {
		return nil, adminFail(admin.CodeNotFound)
	}
	if l.epoch != req.Epoch || l.legs != req.Legs {
		return nil, adminFail(admin.CodeMismatch)
	}
	rec := journal.Record{Kind: journal.KindClear, UID: lk.uid, Host: lk.host, Root: lk.root,
		Epoch: l.epoch + 1, Reason: req.Reason, At: c.now().Unix()}
	if err := c.journal.Append(rec); err != nil {
		c.degraded = true
		return nil, adminFail(admin.CodeUnavailable)
	}
	c.applyClear(lk, rec)

	var sessions []admin.Session
	for sk, s := range c.sessions {
		if sk.uid == lk.uid && sk.host == lk.host && s.root == lk.root {
			sessions = append(sessions, admin.Session{Session: sk.session, Current: false, At: s.at})
		}
	}
	slices.SortFunc(sessions, func(a, b admin.Session) int { return strings.Compare(a.Session, b.Session) })
	return &admin.ClearResponse{Version: admin.Version, Lineage: c.view(lk, sessions)}, nil
}
