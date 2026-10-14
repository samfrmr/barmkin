// Barmkin-monitor is the local barmkin monitor and its demo client.
//
// Usage:
//
//	barmkin-monitor serve  -socket PATH -journal PATH
//	barmkin-monitor decide -socket PATH -session ID -operation routine|protected
//	barmkin-monitor taint  -socket PATH -session ID [-source untrusted-input]
//	barmkin-monitor send   -socket PATH -path /v1/... -body JSON
//
// decide and send print the decision as JSON and exit 0 for allow, 2 for
// deny - including when the monitor is unreachable. taint exits 0 only
// when the monitor confirms the taint was durably recorded. send posts raw
// bytes so fixtures can show malformed and unknown requests being denied.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Daviey/barmkin/monitor"
)

const clientTimeout = 2 * time.Second

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	switch cmd {
	case "serve":
		os.Exit(cmdServe(args))
	case "decide":
		os.Exit(cmdDecide(args))
	case "taint":
		os.Exit(cmdTaint(args))
	case "send":
		os.Exit(cmdSend(args))
	default:
		usage()
	}
}

func cmdServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	socket := fs.String("socket", "", "Unix socket path to listen on")
	journalPath := fs.String("journal", "", "taint journal path")
	fs.Parse(args)
	requireFlags(fs, *socket, *journalPath)

	// Take the journal lock before touching the socket, so a second
	// monitor can never replace a live monitor's socket.
	journal, records, err := monitor.OpenJournal(*journalPath)
	if err != nil {
		return fail("%v", err)
	}
	defer journal.Close()

	ln, err := monitor.Listen(*socket)
	if err != nil {
		return fail("listen: %v", err)
	}
	defer os.Remove(*socket)

	srv := monitor.NewHTTPServer(monitor.NewServer(journal, records))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "[barmkin-monitor] serving v%d on %s (%d journaled taint(s) replayed)\n",
		monitor.Version, *socket, len(records))
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fail("serve: %v", err)
	}
	return 0
}

func cmdDecide(args []string) int {
	fs := flag.NewFlagSet("decide", flag.ExitOnError)
	socket := fs.String("socket", "", "monitor Unix socket path")
	session := fs.String("session", "", "opaque session token")
	op := fs.String("operation", "", "routine or protected")
	fs.Parse(args)
	requireFlags(fs, *socket, *session, *op)

	resp := client(*socket).Decide(context.Background(), *session, monitor.Operation(*op))
	return printDecision(resp)
}

func cmdTaint(args []string) int {
	fs := flag.NewFlagSet("taint", flag.ExitOnError)
	socket := fs.String("socket", "", "monitor Unix socket path")
	session := fs.String("session", "", "opaque session token")
	source := fs.String("source", string(monitor.SourceUntrustedInput), "taint source")
	fs.Parse(args)
	requireFlags(fs, *socket, *session, *source)

	resp, err := client(*socket).Taint(context.Background(), *session, monitor.TaintSource(*source))
	printJSON(resp)
	if err != nil {
		return fail("%v", err)
	}
	return 0
}

func cmdSend(args []string) int {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	socket := fs.String("socket", "", "monitor Unix socket path")
	path := fs.String("path", monitor.PathDecide, "request path")
	body := fs.String("body", "", "raw request body")
	fs.Parse(args)
	requireFlags(fs, *socket)

	status, raw, err := client(*socket).Post(context.Background(), *path, []byte(*body))
	if err != nil {
		return printDecision(monitor.DecideResponse{
			Version: monitor.Version, Decision: monitor.Deny, Reason: monitor.ReasonMonitorUnavailable,
		})
	}
	return printDecision(monitor.InterpretDecide(status, raw))
}

func client(socket string) *monitor.Client {
	return monitor.NewClient(socket, clientTimeout)
}

// printDecision prints resp and returns the barmkin exit convention:
// 0 allow, 2 deny.
func printDecision(resp monitor.DecideResponse) int {
	printJSON(resp)
	if resp.Decision == monitor.Allow {
		return 0
	}
	return 2
}

func printJSON(v any) {
	out, _ := json.Marshal(v)
	fmt.Println(string(out))
}

func requireFlags(fs *flag.FlagSet, values ...string) {
	for _, v := range values {
		if v == "" {
			fmt.Fprintf(os.Stderr, "[barmkin-monitor] %s: missing required flag\n", fs.Name())
			fs.Usage()
			os.Exit(1)
		}
	}
}

func fail(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "[barmkin-monitor] "+format+"\n", args...)
	return 1
}

func usage() {
	fmt.Fprint(os.Stderr, `barmkin-monitor - local barmkin monitor (contract v1)

Usage:
  barmkin-monitor serve  -socket PATH -journal PATH
  barmkin-monitor decide -socket PATH -session ID -operation routine|protected
  barmkin-monitor taint  -socket PATH -session ID [-source untrusted-input]
  barmkin-monitor send   -socket PATH -path /v1/... -body JSON

decide and send exit 0 for allow and 2 for deny; an unreachable
monitor is a deny.
`)
	os.Exit(1)
}
