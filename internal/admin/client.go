package admin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Deadline bounds each administrative request.
const Deadline = 10 * time.Second

// Client talks to the administrative socket.
type Client struct{ hc *http.Client }

// NewClient returns a client of the administrative socket at socket.
func NewClient(socket string) *Client {
	return &Client{hc: &http.Client{
		Timeout: Deadline,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
		},
	}}
}

// List returns every lineage.
func (c *Client) List(ctx context.Context) (*ListResponse, error) {
	var resp ListResponse
	if err := c.do(ctx, OpList, &ListRequest{Version: Version}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Clear clears one lineage, and returns it as the monitor journaled it.
func (c *Client) Clear(ctx context.Context, req ClearRequest) (*ClearResponse, error) {
	req.Version = Version
	var resp ClearResponse
	if err := c.do(ctx, OpClear, &req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) do(ctx context.Context, op Op, req, resp Message) error {
	body, err := Encode(req)
	if err != nil {
		return err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://barmkin-admin"+op.Path(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	hr.Header.Set("Content-Type", "application/json")
	r, err := c.hc.Do(hr)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	out, err := io.ReadAll(io.LimitReader(r.Body, MaxResponseBytes+1))
	if err != nil {
		return err
	}
	if r.StatusCode != http.StatusOK {
		var e ErrorResponse
		if Decode(out, MaxResponseBytes, &e) != nil || e.Error.HTTPStatus() != r.StatusCode {
			return fmt.Errorf("monitor answered HTTP %d with no valid error", r.StatusCode)
		}
		return &Error{Code: e.Error}
	}
	if err := Decode(out, MaxResponseBytes, resp); err != nil {
		return errors.New("monitor answered with an invalid reply")
	}
	return nil
}

// CheckSocket requires the administrative socket at path to be a socket
// owned by uid with no group or other access, in a directory owned by uid
// that no one else can enter, under directories owned by root or uid and
// writable by no one else unless sticky. Root runs it before connecting, so
// it never talks to a socket another user created.
func CheckSocket(path string, uid int) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s is not an absolute path", path)
	}
	path = filepath.Clean(path)
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if err := private(path, fi, uid, os.ModeSocket); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if fi, err = os.Lstat(dir); err != nil {
		return err
	}
	if err := private(dir, fi, uid, os.ModeDir); err != nil {
		return err
	}
	for p := filepath.Dir(dir); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		switch {
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case owner(fi) != 0 && owner(fi) != uid:
			return fmt.Errorf("%s is owned by uid %d, not root", p, owner(fi))
		case fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0:
			return fmt.Errorf("%s is writable by group or other", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func private(path string, fi os.FileInfo, uid int, kind os.FileMode) error {
	switch {
	case fi.Mode().Type() != kind:
		return fmt.Errorf("%s is a %v, not a %v", path, fi.Mode().Type(), kind)
	case owner(fi) != uid:
		return fmt.Errorf("%s is owned by uid %d, not %d", path, owner(fi), uid)
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("%s has mode %#o; it must allow no group or other access", path, fi.Mode().Perm())
	}
	return nil
}

func owner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
