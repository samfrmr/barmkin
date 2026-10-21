package jevproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// healthPath is reserved for the proxy's own fast-fail health check and is
// never forwarded upstream. It cannot collide with a real OpenRouter call,
// which is always under /api/.
const healthPath = "/healthz"

// forwardedRequestHeaders is the allowlist copied from a caller's request
// to the upstream request. Everything else, including any Authorization,
// Proxy-Authorization, Cookie or Host the caller sent, is dropped: the
// proxy is the only party that sets Authorization, and nothing a caller
// sends can override that or redirect the call.
var forwardedRequestHeaders = []string{"Content-Type", "Accept"}

// forwardedResponseHeaders is the allowlist copied from the upstream reply
// back to the caller.
var forwardedResponseHeaders = []string{"Content-Type"}

// handler returns the proxy's http.Handler: the health check at
// healthPath, and pass-through to the pinned upstream for everything else.
func (p *Proxy) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath {
			p.serveHealth(w, r)
			return
		}
		p.serveForward(w, r)
	})
}

func (p *Proxy) serveHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"state": "ok"})
}

// serveForward passes r's path, query, method and body through to the
// pinned upstream unchanged, adding the proxy's own Authorization header.
// It never relays a redirect, never forwards a caller-supplied
// Authorization, Cookie or Host, and bounds both the request and the
// response to cfg.MaxBodyBytes within cfg.Timeout.
func (p *Proxy) serveForward(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, p.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "request body too large or unreadable", http.StatusRequestEntityTooLarge)
		return
	}

	target := p.cfg.Upstream + singleJoiningSlash(r.URL.Path)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	u, err := url.Parse(target)
	if err != nil {
		http.Error(w, "bad request path", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.cfg.Timeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), bytes.NewReader(body))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for _, h := range forwardedRequestHeaders {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	out.Header.Set("Authorization", "Bearer "+p.key.Value())
	out.Header.Set("User-Agent", "barmkin-jevproxy/1")

	start := time.Now()
	resp, err := p.rt.RoundTrip(out)
	if err != nil {
		p.logf("jev-proxy: upstream call failed after %s: %v", time.Since(start), redactErr(err))
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		// Never relay or follow a redirect: the pinned upstream base is
		// the only destination this proxy ever sends a byte to.
		p.logf("jev-proxy: upstream answered a redirect (%d); refusing", resp.StatusCode)
		http.Error(w, "upstream redirect refused", http.StatusBadGateway)
		return
	}

	limited := io.LimitReader(resp.Body, p.cfg.MaxBodyBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		http.Error(w, "upstream response unreadable", http.StatusBadGateway)
		return
	}
	if int64(len(data)) > p.cfg.MaxBodyBytes {
		http.Error(w, "upstream response too large", http.StatusBadGateway)
		return
	}

	for _, h := range forwardedResponseHeaders {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(data)
}

// singleJoiningSlash ensures the forwarded path starts with exactly one
// slash, so it joins cleanly onto the upstream base URL, which has none.
func singleJoiningSlash(path string) string {
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

// redactErr guards against a transport error embedding the Authorization
// header or key (net/http errors do not, but this keeps the diagnostic
// path honest if that ever changes upstream).
func redactErr(err error) string {
	msg := err.Error()
	if strings.Contains(msg, "Bearer ") {
		return redacted
	}
	return msg
}
