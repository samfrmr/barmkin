package jevproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServeForwardPassesPathQueryAndBody(t *testing.T) {
	var gotMethod, gotPath, gotQuery, gotBody, gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		buf := make([]byte, r.ContentLength)
		r.Body.Read(buf)
		gotBody = string(buf)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL)
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions?stream=true", `{"model":"x"}`, map[string]string{
		"Content-Type": "application/json",
	})

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	if gotPath != "/api/v1/chat/completions" {
		t.Errorf("upstream path = %q, want /api/v1/chat/completions", gotPath)
	}
	if gotQuery != "stream=true" {
		t.Errorf("upstream query = %q, want stream=true", gotQuery)
	}
	if gotBody != `{"model":"x"}` {
		t.Errorf("upstream body = %q, want the caller's body unchanged", gotBody)
	}
	if gotAuth != "Bearer "+testKey {
		t.Errorf("upstream Authorization = %q, want the proxy's own key", gotAuth)
	}
	if rr.Body.String() != `{"ok":true}` {
		t.Errorf("response body = %q, want the upstream's body relayed", rr.Body.String())
	}
}

// TestServeForwardStripsCallerAuth is the header-injection check: a caller
// that sends its own Authorization, Proxy-Authorization or Cookie must
// never have it reach the upstream, and can never override the proxy's
// own Authorization. A caller holds no key of its own (auth.type: none);
// anything it sends in these headers is an injection attempt, not a
// credential.
func TestServeForwardStripsCallerAuth(t *testing.T) {
	var gotHeaders http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL)
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions", `{}`, map[string]string{
		"Authorization":       "Bearer sk-caller-supplied-should-not-reach-upstream",
		"Proxy-Authorization": "Basic should-not-reach-upstream",
		"Cookie":              "session=should-not-reach-upstream",
		"X-Forwarded-For":     "127.0.0.1",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if got := gotHeaders.Get("Authorization"); got != "Bearer "+testKey {
		t.Errorf("Authorization = %q, want the proxy's own key, not the caller's", got)
	}
	for _, h := range []string{"Proxy-Authorization", "Cookie", "X-Forwarded-For"} {
		if got := gotHeaders.Get(h); got != "" {
			t.Errorf("caller header %s = %q reached upstream, want it dropped", h, got)
		}
	}
}

// TestServeForwardRefusesRedirect proves the proxy never follows, and
// never relays, a redirect the upstream sends: a 3xx becomes a 502 to the
// caller, and the upstream sees exactly one request, never a second one
// to whatever Location it named.
func TestServeForwardRefusesRedirect(t *testing.T) {
	var requests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Location", "https://attacker.example/steal")
		w.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL)
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions", `{}`, nil)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (redirect refused)", rr.Code, http.StatusBadGateway)
	}
	if strings.Contains(rr.Body.String(), "attacker.example") {
		t.Errorf("the redirect target leaked into the response: %s", rr.Body.String())
	}
	if n := requests.Load(); n != 1 {
		t.Errorf("upstream saw %d requests, want exactly 1 (no following the redirect)", n)
	}
}

// TestServeForwardBoundsRequestSize proves a caller cannot hold the proxy
// open with an oversized request body.
func TestServeForwardBoundsRequestSize(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the oversized request must never reach upstream")
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, func(cfg *Config) { cfg.MaxBodyBytes = 16 })
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions", strings.Repeat("x", 17), nil)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

// TestServeForwardBoundsResponseSize proves an oversized upstream reply
// does not get relayed either.
func TestServeForwardBoundsResponseSize(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("y", 17)))
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, func(cfg *Config) { cfg.MaxBodyBytes = 16 })
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions", `{}`, nil)
	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (oversized upstream response)", rr.Code, http.StatusBadGateway)
	}
}

// TestServeForwardTimesOutOnHungUpstream proves the proxy fails fast
// against a hung upstream instead of holding the caller open indefinitely,
// so a caller's own breaker trips instantly rather than waiting out a
// stall.
func TestServeForwardTimesOutOnHungUpstream(t *testing.T) {
	// The handler outlasts the proxy's own timeout but still returns well
	// before the test does, so the deferred Close below does not itself
	// have to wait on client-side cancellation reaching the server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL, func(cfg *Config) { cfg.Timeout = 100 * time.Millisecond })
	start := time.Now()
	rr := doRequest(t, p, "POST", "/api/v1/chat/completions", `{}`, nil)
	elapsed := time.Since(start)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
	if elapsed > time.Second {
		t.Errorf("took %s to fail against a hung upstream, want well under the 1s shim deadline budget", elapsed)
	}
}

func TestHealthEndpoint(t *testing.T) {
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
	}))
	defer upstream.Close()

	p := newTestProxy(t, upstream.URL)
	rr := doRequest(t, p, "GET", healthPath, "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"ok"`) {
		t.Errorf("health body = %q, want it to report ok", rr.Body.String())
	}
	if n := upstreamCalls.Load(); n != 0 {
		t.Errorf("health check made %d upstream calls, want 0 (no key needed, no network)", n)
	}
}

func TestHealthEndpointRefusesNonGet(t *testing.T) {
	p := newTestProxy(t, "https://openrouter.ai")
	rr := doRequest(t, p, "POST", healthPath, "", nil)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}
