package jevproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// newUpstreamTransport returns a RoundTripper that will dial only the host
// and port parsed from upstream, and nothing else: no proxy environment
// variables, no redirect following (RoundTrip never follows redirects; see
// handler.go for how a 3xx reply is refused rather than relayed), and no
// per-host address the caller can influence. upstream must be an https URL
// with no user info, path, query or fragment.
func newUpstreamTransport(upstream string) (http.RoundTripper, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("upstream scheme must be https, got %q", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("upstream must be a bare https://host base URL, got %q", upstream)
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("upstream has no host: %q", upstream)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	pinned := net.JoinHostPort(host, port)

	return &http.Transport{
		Proxy: nil, // proxy environment variables never apply
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if addr != pinned {
				return nil, fmt.Errorf("refusing to dial %q: only %q is permitted", addr, pinned)
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConnsPerHost: 8,
		MaxConnsPerHost:     16,
	}, nil
}
