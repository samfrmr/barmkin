package jevproxy

import (
	"context"
	"fmt"
	"net"
)

// DialPinned connects to the Jev proxy's Unix socket and checks, by the
// kernel's peer credentials (SO_PEERCRED), that the process serving it
// runs as uid. This is the listener-uid pin pattern: it detects a same-uid
// impostor that raced the real, root-owned proxy to the socket path (for
// example while the unit is restarting), and refuses to send it anything.
// A caller presents no credential of its own; this check, done before a
// single byte is written, is what it trusts instead.
//
// A production caller pins uid 0, the proxy's required service uid
// (wantServiceUID). It is a parameter, not a constant, so tests can pin
// their own uid without needing to be root.
func DialPinned(ctx context.Context, socket string, uid uint32) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socket)
	if err != nil {
		return nil, err
	}
	got, err := peerUID(conn.(*net.UnixConn))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jev proxy socket: reading peer uid: %w", err)
	}
	if got != uid {
		conn.Close()
		return nil, fmt.Errorf("jev proxy socket %s is served by uid %d, not %d: refusing a same-uid impostor listener", socket, got, uid)
	}
	return conn, nil
}
