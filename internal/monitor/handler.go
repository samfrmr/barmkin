package monitor

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/Daviey/barmkin/internal/proto"
)

type peerKey struct{}

// withPeer records the uid of the process at the other end of the
// connection a request arrived on.
func withPeer(ctx context.Context, uid uint32) context.Context {
	return context.WithValue(ctx, peerKey{}, uid)
}

func peerFrom(ctx context.Context) (uint32, bool) {
	uid, ok := ctx.Value(peerKey{}).(uint32)
	return uid, ok
}

// ServeHTTP answers one operation of the internal/proto contract. A request
// with no peer identity is answered unavailable.
func (c *core) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op, ok := proto.ParsePath(r.URL.Path)
	if !ok || r.Method != http.MethodPost || r.URL.RawQuery != "" {
		writeError(w, proto.CodeBadRequest)
		return
	}
	uid, ok := peerFrom(r.Context())
	if !ok {
		writeError(w, proto.CodeUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, proto.MaxBodyBytes+1))
	if err != nil {
		writeError(w, proto.CodeBadRequest)
		return
	}
	req, _ := proto.NewRequest(op)
	if err := proto.Decode(body, req); err != nil {
		writeError(w, codeOf(err))
		return
	}
	resp, err := c.handle(uid, req)
	if err != nil {
		writeError(w, codeOf(err))
		return
	}
	out, err := proto.Encode(resp)
	if err != nil {
		writeError(w, proto.CodeUnavailable)
		return
	}
	write(w, http.StatusOK, out)
}

func codeOf(err error) proto.Code {
	if pe, ok := errors.AsType[*proto.Error](err); ok {
		return pe.Code
	}
	return proto.CodeUnavailable
}

func writeError(w http.ResponseWriter, code proto.Code) {
	out, err := proto.Encode(&proto.ErrorResponse{Version: proto.Version, Error: code})
	if err != nil {
		code = proto.CodeUnavailable
		out = []byte(`{"version":1,"error":"unavailable"}`)
	}
	write(w, code.HTTPStatus(), out)
}

func write(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}
