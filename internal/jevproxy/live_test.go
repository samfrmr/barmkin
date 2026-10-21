//go:build linux

package jevproxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// TestLiveOpenRouterCall runs the proxy end to end against the real
// OpenRouter API: a real key, a real TLS connection to openrouter.ai, and
// a real response. It is opt-in and must never run in CI or by default:
// set BARMKIN_JEV_LIVE_TEST=1 and BARMKIN_JEV_LIVE_KEY (a real OpenRouter
// API key) to run it, for example in a developer's own shell before
// shipping a change to the transport or the handler.
//
//	BARMKIN_JEV_LIVE_TEST=1 BARMKIN_JEV_LIVE_KEY=sk-or-v1-... \
//		go test ./internal/jevproxy/... -run TestLiveOpenRouterCall -v
func TestLiveOpenRouterCall(t *testing.T) {
	if os.Getenv("BARMKIN_JEV_LIVE_TEST") != "1" {
		t.Skip("opt-in only: set BARMKIN_JEV_LIVE_TEST=1 and BARMKIN_JEV_LIVE_KEY to call the real OpenRouter API; never run this in CI")
	}
	key := os.Getenv("BARMKIN_JEV_LIVE_KEY")
	if key == "" {
		t.Fatal("BARMKIN_JEV_LIVE_TEST=1 but BARMKIN_JEV_LIVE_KEY is empty")
	}

	cfg := deployment(t)
	if err := os.WriteFile(cfg.KeyPath, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Upstream = DefaultUpstream
	cfg.Timeout = 10 * time.Second

	p, err := Start(cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- p.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return DialPinned(ctx, cfg.Socket, uint32(os.Getuid()))
			},
		},
	}
	// GET /api/v1/models is a read-only, unauthenticated-safe OpenRouter
	// endpoint, so a live run never spends budget or causes a side effect.
	resp, err := client.Get("http://jevproxy/api/v1/models")
	if err != nil {
		t.Fatalf("GET /api/v1/models: %v", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d: %s", resp.StatusCode, data)
	}
	if len(data) == 0 {
		t.Error("empty response body from a live OpenRouter call")
	}
}
