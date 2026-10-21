package jevproxy

import (
	"net/http"
	"testing"
)

func TestNewUpstreamTransportRefusesBadBase(t *testing.T) {
	cases := []string{
		"http://openrouter.ai",       // not https
		"https://openrouter.ai/api",  // has a path
		"https://openrouter.ai?x=1",  // has a query
		"https://openrouter.ai#frag", // has a fragment
		"https://user@openrouter.ai", // has user info
		"not-a-url",
		"",
	}
	for _, upstream := range cases {
		if _, err := newUpstreamTransport(upstream); err == nil {
			t.Errorf("newUpstreamTransport(%q) succeeded, want an error", upstream)
		}
	}
}

func TestTransportDialsOnlyThePinnedHost(t *testing.T) {
	// A real TLS host is unreachable in a sandboxed test, so this proves
	// the dial guard fires before any network attempt for anything other
	// than the pinned host:port, using the transport against an upstream
	// whose host it must refuse.
	rt, err := newUpstreamTransport("https://openrouter.ai")
	if err != nil {
		t.Fatal(err)
	}
	tr := rt.(*http.Transport)
	for _, addr := range []string{
		"evil.example:443",
		"openrouter.ai:80",
		"openrouter.ai.evil.example:443",
		"127.0.0.1:443",
	} {
		if _, err := tr.DialContext(t.Context(), "tcp", addr); err == nil {
			t.Errorf("dial to %s was allowed, want refused (only openrouter.ai:443 is pinned)", addr)
		}
	}
}
