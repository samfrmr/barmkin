// Jev-proxy runs the root-owned Jev proxy (internal/jevproxy).
//
//	barmkin jev-proxy [-socket PATH] [-key PATH] [-caller-group NAME]
//	                  [-upstream URL] [-timeout DURATION] [-max-body-bytes N]
//
// It is meant to run as root, under a root-managed unit: it is the only
// process that reads the OpenRouter API key (-key, root-owned mode 0600),
// so no agent-uid component, including the barmkin monitor, ever holds
// it. A caller authenticates by connecting to -socket; it presents no key
// of its own. It serves until SIGINT or SIGTERM, then exits 0; it exits 1
// when its deployment checks fail or it cannot serve.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Daviey/barmkin/internal/jevproxy"
)

func cmdJevProxy(args []string) {
	fs := flag.NewFlagSet("jev-proxy", flag.ExitOnError)
	cfg := jevproxy.Config{Logf: func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[barmkin jev-proxy] "+format+"\n", args...)
	}}
	fs.StringVar(&cfg.Socket, "socket", jevproxy.DefaultSocket, "caller Unix socket path")
	fs.StringVar(&cfg.KeyPath, "key", jevproxy.DefaultKeyPath, "root-owned, mode-0600 file holding the OpenRouter API key")
	fs.StringVar(&cfg.CallerGroup, "caller-group", jevproxy.DefaultCallerGroup, "group allowed to connect to the socket")
	fs.StringVar(&cfg.Upstream, "upstream", jevproxy.DefaultUpstream, "pinned upstream base URL (https only)")
	fs.DurationVar(&cfg.Timeout, "timeout", jevproxy.DefaultTimeout, "per-request timeout, end to end")
	fs.Int64Var(&cfg.MaxBodyBytes, "max-body-bytes", jevproxy.DefaultMaxBodyBytes, "bound on a request or response body")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatalf("jev-proxy: unexpected argument %q", fs.Arg(0))
	}

	p, err := jevproxy.Start(cfg)
	if err != nil {
		fatalf("jev-proxy: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg.Logf("serving on %s, upstream %s", cfg.Socket, cfg.Upstream)
	if err := p.Serve(ctx); err != nil {
		fatalf("jev-proxy: %v", err)
	}
}
