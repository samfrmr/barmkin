package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/proto"
)

// socketDir returns a directory whose paths fit in a Unix socket address.
func socketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "bmkc")
	if err == nil && len(dir) > 80 {
		os.RemoveAll(dir)
		dir, err = os.MkdirTemp("/tmp", "bmkc")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// serve answers every request on a new Unix socket with handler.
func serve(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(socketDir(t), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

// serveRaw writes reply to every connection on a new Unix socket after
// reading the request head, then closes it.
func serveRaw(t *testing.T, reply func(net.Conn)) string {
	t.Helper()
	sock := filepath.Join(socketDir(t), "m.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				conn.Read(make([]byte, 4096))
				reply(conn)
			}()
		}
	}()
	return sock
}

func reply(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

func gateReq() *proto.GateRequest {
	return &proto.GateRequest{Version: proto.Version, Host: proto.HostClaudeCode, Session: "sess-a", Call: "toolu_01A"}
}

func do(sock string, c Client) (proto.GateResponse, error) {
	c.Socket = sock
	if c.Timeout == 0 {
		c.Timeout = 300 * time.Millisecond
	}
	var resp proto.GateResponse
	err := c.Do(context.Background(), proto.OpGate, gateReq(), &resp)
	return resp, err
}

func TestDoSendsOneContentFreeRequest(t *testing.T) {
	var got atomic.Value
	sock := serve(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.Store(r.Method + " " + r.URL.Path + " " + r.Header.Get("Content-Type") + " " + string(body))
		reply(200, `{"version":1,"preregistered":true}`)(w, r)
	})
	resp, err := do(sock, Client{})
	if err != nil || !resp.Preregistered {
		t.Fatalf("Do = %+v, %v", resp, err)
	}
	want := `POST /v1/gate application/json {"version":1,"host":"claude_code","session":"sess-a","call":"toolu_01A"}`
	if got.Load() != want {
		t.Fatalf("request %q, want %q", got.Load(), want)
	}
}

func TestDoErrors(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{"error code", reply(404, `{"version":1,"error":"unknown_session"}`), &proto.Error{Code: proto.CodeUnknownSession}},
		{"unavailable code", reply(503, `{"version":1,"error":"unavailable"}`), &proto.Error{Code: proto.CodeUnavailable}},
		{"bad request code", reply(400, `{"version":1,"error":"bad_request"}`), &proto.Error{Code: proto.CodeBadRequest}},
		{"version mismatch code", reply(400, `{"version":1,"error":"version_mismatch"}`), &proto.Error{Code: proto.CodeVersionMismatch}},
		{"error code with the wrong status", reply(503, `{"version":1,"error":"unknown_session"}`), ErrMalformed},
		{"success body with an error status", reply(500, `{"version":1,"preregistered":true}`), ErrMalformed},
		{"reply from another version", reply(200, `{"version":2,"preregistered":true}`), &proto.Error{Code: proto.CodeVersionMismatch}},
		{"error from another version", reply(400, `{"version":2,"error":"version_mismatch"}`), &proto.Error{Code: proto.CodeVersionMismatch}},
		{"reply without version", reply(200, `{"preregistered":true}`), ErrMalformed},
		{"reply with an unknown field", reply(200, `{"version":1,"preregistered":true,"allow":true}`), ErrMalformed},
		{"plain text", reply(200, `ok`), ErrMalformed},
		{"oversized reply", reply(200, `{"version":1,"preregistered":true,"x":"`+strings.Repeat("a", proto.MaxBodyBytes)+`"}`), ErrMalformed},
		{"stalled", func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }, ErrUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := do(serve(t, c.handler), Client{})
			assertErr(t, err, c.want)
		})
	}
}

func assertErr(t *testing.T, err, want error) {
	t.Helper()
	if pe, ok := want.(*proto.Error); ok {
		got, ok := errors.AsType[*proto.Error](err)
		if !ok || got.Code != pe.Code {
			t.Fatalf("err %v, want %v", err, want)
		}
		return
	}
	if !errors.Is(err, want) {
		t.Fatalf("err %v, want %v", err, want)
	}
}

func TestDoRawReplies(t *testing.T) {
	cases := []struct {
		name  string
		reply func(net.Conn)
		want  error
	}{
		{"closed without a reply", func(net.Conn) {}, ErrUnavailable},
		{"not HTTP", func(c net.Conn) { io.WriteString(c, "hello\r\n\r\n") }, ErrUnavailable},
		{"truncated body", func(c net.Conn) {
			io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{\"version\":1")
		}, ErrUnavailable},
		{"endless headers", func(c net.Conn) {
			io.WriteString(c, "HTTP/1.1 200 OK\r\n")
			line := []byte("X-Pad: " + strings.Repeat("a", 1000) + "\r\n")
			for range 200 {
				if _, err := c.Write(line); err != nil {
					return
				}
			}
		}, ErrUnavailable},
		{"endless body", func(c net.Conn) {
			io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n{\"version\":1,\"x\":\"")
			chunk := []byte(strings.Repeat("a", 4096))
			for range 64 {
				if _, err := c.Write(chunk); err != nil {
					return
				}
			}
		}, ErrMalformed},
		{"chunked", func(c net.Conn) {
			body := `{"version":1,"preregistered":true}`
			fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := do(serveRaw(t, c.reply), Client{})
			if c.want == nil {
				if err != nil || !resp.Preregistered {
					t.Fatalf("Do = %+v, %v", resp, err)
				}
				return
			}
			assertErr(t, err, c.want)
		})
	}
}

func TestDoUnreachable(t *testing.T) {
	_, err := do(filepath.Join(socketDir(t), "absent.sock"), Client{})
	assertErr(t, err, ErrUnavailable)
}

func TestDoTimeoutBoundsTheExchange(t *testing.T) {
	sock := serveRaw(t, func(c net.Conn) {
		io.WriteString(c, "HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{")
		time.Sleep(2 * time.Second)
	})
	start := time.Now()
	_, err := do(sock, Client{Timeout: 100 * time.Millisecond})
	assertErr(t, err, ErrUnavailable)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Do returned after %s, want about 100ms", elapsed)
	}
}

func TestDoCancelledContext(t *testing.T) {
	sock := serve(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(50*time.Millisecond, cancel)
	start := time.Now()
	var resp proto.GateResponse
	err := Client{Socket: sock, Timeout: 5 * time.Second}.Do(ctx, proto.OpGate, gateReq(), &resp)
	assertErr(t, err, ErrUnavailable)
	if ctx.Err() == nil {
		t.Fatal("context not cancelled")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Do returned after %s, want soon after the cancel", elapsed)
	}
}

func TestDoDefaultTimeout(t *testing.T) {
	sock := serve(t, func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
	start := time.Now()
	var resp proto.GateResponse
	err := Client{Socket: sock}.Do(context.Background(), proto.OpGate, gateReq(), &resp)
	assertErr(t, err, ErrUnavailable)
	if elapsed := time.Since(start); elapsed < proto.ClientDeadline/2 || elapsed > 2*proto.ClientDeadline {
		t.Fatalf("Do returned after %s, want about %s", elapsed, proto.ClientDeadline)
	}
}

func TestDoRefusesInvalidRequest(t *testing.T) {
	var hits atomic.Int32
	sock := serve(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		reply(200, `{"version":1,"preregistered":true}`)(w, r)
	})
	req := gateReq()
	req.Call = "toolu 01A"
	var resp proto.GateResponse
	err := Client{Socket: sock}.Do(context.Background(), proto.OpGate, req, &resp)
	assertErr(t, err, &proto.Error{Code: proto.CodeBadRequest})
	if hits.Load() != 0 {
		t.Fatal("an invalid request was sent")
	}
}

func TestDoPinsThePeerUID(t *testing.T) {
	sock := serve(t, reply(200, `{"version":1,"preregistered":true}`))
	self := uint32(os.Getuid())
	if resp, err := do(sock, Client{PeerUID: &self}); err != nil || !resp.Preregistered {
		t.Fatalf("pinned to the server's own uid: %+v, %v", resp, err)
	}
	other := self + 1
	_, err := do(sock, Client{PeerUID: &other})
	assertErr(t, err, ErrPeer)
}
