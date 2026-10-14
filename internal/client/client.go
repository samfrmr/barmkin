// Package client is the Go client for the barmkin monitor's socket
// contract (internal/proto). The managed gate (`barmkin gate`) uses it.
//
// It fails closed. A request either returns the monitor's well-formed
// success reply or an error, and every error means the caller must treat
// the guarded step as denied:
//
//   - [ErrUnavailable]: the socket could not be reached, or the exchange
//     failed or ran past its deadline;
//   - [ErrPeer]: the process serving the socket does not run as the pinned
//     monitor uid;
//   - [ErrMalformed]: the reply is not a well-formed contract message, or
//     its HTTP status does not match its error code;
//   - a *proto.Error: the monitor answered that error code, or the reply
//     came from another contract version (version_mismatch).
//
// Each request is one short HTTP/1.1 exchange on its own connection, read
// with net/http's response parser and no transport, connection pool or
// background goroutine. The whole exchange is bounded by one deadline and
// a byte limit, so a stalled or flooding peer cannot hold the caller.
package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Daviey/barmkin/internal/proto"
)

var (
	// ErrUnavailable: the monitor could not be reached, or the exchange
	// failed or timed out.
	ErrUnavailable = errors.New("monitor unavailable")
	// ErrPeer: the socket is served by a process that does not run as the
	// pinned monitor uid, or whose uid cannot be read.
	ErrPeer = errors.New("monitor socket served by an unexpected uid")
	// ErrMalformed: the reply is not a well-formed contract message.
	ErrMalformed = errors.New("malformed monitor reply")
)

// maxHeaderBytes bounds the status line and headers of a reply. The
// monitor sends a handful of short headers.
const maxHeaderBytes = 16 << 10

// Client sends contract requests to a monitor socket. The zero Timeout
// means proto.ClientDeadline.
type Client struct {
	Socket  string        // monitor Unix socket path
	PeerUID *uint32       // when set, the uid the socket's server must run as
	Timeout time.Duration // bounds each request end to end
}

// Do sends req as op and decodes the monitor's success reply into resp. It
// returns nil only for an HTTP 200 carrying a well-formed resp; see the
// package doc for the errors. A request that does not encode returns its
// bad_request *proto.Error without being sent.
func (c Client) Do(ctx context.Context, op proto.Op, req, resp proto.Message) error {
	body, err := proto.Encode(req)
	if err != nil {
		return err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = proto.ClientDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := c.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	// A cancelled ctx ends the exchange at once, not at the deadline.
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	head := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: barmkin\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		op.Path(), len(body))
	if _, err := conn.Write(append([]byte(head), body...)); err != nil {
		return unavailable(err)
	}
	limited := io.LimitReader(conn, maxHeaderBytes+proto.MaxBodyBytes+1)
	r, err := http.ReadResponse(bufio.NewReader(limited), nil)
	if err != nil {
		return unavailable(err)
	}
	defer r.Body.Close()
	data, err := io.ReadAll(io.LimitReader(r.Body, proto.MaxBodyBytes+1))
	if err != nil {
		return unavailable(err)
	}

	if r.StatusCode != http.StatusOK {
		var e proto.ErrorResponse
		if err := proto.Decode(data, &e); err != nil {
			return decodeFailure(err)
		}
		if e.Error.HTTPStatus() != r.StatusCode {
			return ErrMalformed
		}
		return &proto.Error{Code: e.Error}
	}
	if err := proto.Decode(data, resp); err != nil {
		return decodeFailure(err)
	}
	return nil
}

// dial connects to the socket and, when a uid is pinned, checks by the
// kernel's peer credentials that the server runs as that uid.
func (c Client) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return nil, unavailable(err)
	}
	if c.PeerUID == nil {
		return conn, nil
	}
	uid, err := peerUID(conn.(*net.UnixConn))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrPeer, err)
	}
	if uid != *c.PeerUID {
		conn.Close()
		return nil, fmt.Errorf("%w: uid %d, want %d", ErrPeer, uid, *c.PeerUID)
	}
	return conn, nil
}

func unavailable(err error) error { return fmt.Errorf("%w: %v", ErrUnavailable, err) }

// decodeFailure is the error for a reply that did not decode: another
// contract version, or a malformed reply. A decode failure is never
// reported as bad_request, which would blame the request.
func decodeFailure(err error) error {
	if pe, ok := errors.AsType[*proto.Error](err); ok && pe.Code == proto.CodeVersionMismatch {
		return pe
	}
	return ErrMalformed
}
