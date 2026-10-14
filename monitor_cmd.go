// Monitor runs the barmkin monitor service (internal/monitor).
//
//	barmkin monitor [-socket PATH] [-state-dir PATH] [-client-group NAME]
//	                [-preregister-ttl DURATION] [-admin-socket PATH]
//
// -admin-socket opts in to the root-owned administrative socket at PATH,
// which systemd creates and passes by socket activation; without it there
// is none, and nothing lowers a leg (see internal/admin and
// monitor_admin_cmd.go).
//
// It is meant to run as a dedicated service user, under a root-managed
// unit that creates its state and runtime directories. It serves until
// SIGINT or SIGTERM, then journals a clean stop and exits 0; it exits 1
// when its deployment checks fail or it cannot serve.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/Daviey/barmkin/internal/monitor"
)

func cmdMonitor(args []string) {
	fs := flag.NewFlagSet("monitor", flag.ExitOnError)
	cfg := monitor.Config{Logf: func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[barmkin monitor] "+format+"\n", args...)
	}}
	fs.StringVar(&cfg.Socket, "socket", monitor.DefaultSocket, "client Unix socket path")
	fs.StringVar(&cfg.StateDir, "state-dir", monitor.DefaultStateDir, "state directory holding the journal")
	fs.StringVar(&cfg.ClientGroup, "client-group", monitor.DefaultClientGroup, "group allowed to connect to the socket")
	fs.DurationVar(&cfg.PreregisterTTL, "preregister-ttl", monitor.DefaultPreregisterTTL, "how long a pre-registered call stays live")
	fs.StringVar(&cfg.AdminSocket, "admin-socket", "", "opt in: the root-owned administrative socket systemd passes (default none)")
	fs.Parse(args)
	if fs.NArg() > 0 {
		fatalf("monitor: unexpected argument %q", fs.Arg(0))
	}

	m, err := monitor.Start(cfg)
	if err != nil {
		fatalf("monitor: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg.Logf("serving on %s", cfg.Socket)
	if cfg.AdminSocket != "" {
		cfg.Logf("serving root only on the administrative socket %s", cfg.AdminSocket)
	}
	if err := m.Serve(ctx); err != nil {
		fatalf("monitor: %v", err)
	}
}
