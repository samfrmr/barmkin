package jevproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testKey = "sk-or-v1-test-secret-do-not-leak"

// newTestProxy builds a Proxy against upstreamURL (an httptest server),
// using the plain default transport rather than the host-pinned one
// built by Start: the dial pin is covered on its own in
// TestTransportDialsOnlyThePinnedHost, and these tests exercise the
// handler's own behavior (forwarding, header hygiene, redirect refusal,
// size and timeout bounds) against a local stand-in.
func newTestProxy(t *testing.T, upstreamURL string, mutate ...func(*Config)) *Proxy {
	t.Helper()
	cfg := Config{
		Upstream:     upstreamURL,
		Timeout:      2 * time.Second,
		MaxBodyBytes: 4096,
		Logf:         func(string, ...any) {},
	}
	for _, m := range mutate {
		m(&cfg)
	}
	return &Proxy{
		cfg:  cfg,
		rt:   http.DefaultTransport,
		key:  Secret(testKey),
		logf: cfg.Logf,
	}
}

// doRequest sends a request through p's handler in-process and returns the
// recorded response.
func doRequest(t *testing.T, p *Proxy, method, path string, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	p.handler().ServeHTTP(rr, req)
	return rr
}
