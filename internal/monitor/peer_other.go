//go:build !linux

package monitor

import (
	"errors"
	"net"
)

// peerUID fails outside Linux, so the monitor refuses every connection
// rather than serve one whose peer it cannot identify.
func peerUID(*net.UnixConn) (uint32, error) {
	return 0, errors.New("peer credentials are only supported on Linux")
}
