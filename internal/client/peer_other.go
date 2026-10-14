//go:build !linux

package client

import (
	"errors"
	"net"
)

// peerUID fails outside Linux, so a pinned client refuses every socket
// rather than trust one whose server it cannot identify.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are only supported on Linux")
}
