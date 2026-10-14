// Gate is the managed Claude Code PreToolUse check for shim presence.
//
// A managed-settings PreToolUse hook runs `barmkin gate` on every tool
// call. The barmkin shim plugin registers the same call with the local
// monitor (POST /v1/register); the gate asks the monitor whether that
// registration is live (POST /v1/presence) and allows the call only if it
// is. So a session whose shim is missing, disabled, or broken cannot run
// any tool.
//
// Both requests are versioned and content-free: they carry only Claude
// Code's session_id and tool_use_id, never the tool name or input.
//
// The gate exits 0 to allow and 2 to deny. Every failure denies: missing
// configuration, malformed hook input, an unregistered, expired or already
// consumed call, a malformed monitor reply, an unreachable monitor, and a
// gate that runs out of time. Claude Code treats any other exit code, and
// a hook timeout, as a non-blocking error that lets the call proceed, so
// the gate never exits with another code and always finishes well before
// the hook timeout.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/Daviey/barmkin/monitor"
)

// gateTiming bounds every stage of the gate. deadline is the hard limit
// for the whole process and must stay well below the Claude Code hook
// timeout (10s in the managed-settings recipe).
type gateTiming struct {
	deadline time.Duration // whole gate, enforced by a backstop exit
	stdin    time.Duration // reading the hook input
	wait     time.Duration // waiting for the shim's registration to land
	request  time.Duration // each monitor request
	poll     time.Duration // between presence checks while waiting
}

var gateTimes = gateTiming{
	deadline: 3 * time.Second,
	stdin:    time.Second,
	wait:     1500 * time.Millisecond,
	request:  500 * time.Millisecond,
	poll:     25 * time.Millisecond,
}

// gateMaxInput bounds the hook input. It includes the tool input, so it is
// generous, but a larger payload is denied rather than read without limit.
const gateMaxInput = 64 << 20

// envMonitorSocket names the monitor socket when -socket is not given.
const envMonitorSocket = "BARMKIN_MONITOR_SOCKET"

// cmdGate runs the gate as a process and exits 0 or 2, never anything
// else: a panic or an overrun of the deadline also denies.
func cmdGate(args []string) {
	var once sync.Once
	exit := func(code int) { once.Do(func() { os.Exit(code) }) }

	backstop := time.AfterFunc(gateTimes.deadline, func() {
		once.Do(func() {
			writeGateDeny(os.Stderr, deny(monitor.ReasonDeadlineExceeded))
			os.Exit(2)
		})
	})
	defer backstop.Stop()
	defer func() {
		if recover() != nil {
			once.Do(func() {
				writeGateDeny(os.Stderr, deny(monitor.ReasonMalformedRequest))
				os.Exit(2)
			})
		}
	}()

	exit(runGate(args, os.Stdin, os.Stderr, os.Getenv))
}

// runGate checks one Claude Code PreToolUse call and returns 0 (allow) or
// 2 (deny). On deny it writes the reason and the v1 response to stderr,
// which Claude Code shows to the model.
func runGate(args []string, stdin io.Reader, stderr io.Writer, getenv func(string) string) int {
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(gateTimes.deadline))
	defer cancel()

	resp := gateDecide(ctx, start, args, stdin, getenv)
	if resp.Decision == monitor.Allow {
		return 0
	}
	writeGateDeny(stderr, resp)
	return 2
}

func gateDecide(ctx context.Context, start time.Time, args []string, stdin io.Reader, getenv func(string) string) monitor.DecideResponse {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", getenv(envMonitorSocket), "monitor Unix socket path")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return deny(monitor.ReasonMalformedRequest)
	}
	if *socket == "" {
		return deny(monitor.ReasonMonitorUnavailable)
	}

	session, call, err := readGateInput(ctx, stdin)
	if err != nil {
		return deny(monitor.ReasonMalformedRequest)
	}

	// Claude Code runs the managed gate and the shim's hook in parallel,
	// so the registration may land just after the gate starts. Keep asking
	// while the answer is "unregistered" and the wait lasts; every other
	// answer is final.
	client := monitor.NewClient(*socket, gateTimes.request)
	waitUntil := start.Add(gateTimes.wait)
	for {
		resp := client.Presence(ctx, session, call)
		if resp.Decision == monitor.Allow || resp.Reason != monitor.ReasonUnregistered {
			return resp
		}
		if time.Now().Add(gateTimes.poll).After(waitUntil) {
			return resp
		}
		select {
		case <-ctx.Done():
			return deny(monitor.ReasonDeadlineExceeded)
		case <-time.After(gateTimes.poll):
		}
	}
}

// readGateInput reads the PreToolUse hook input and returns its session
// and tool-call tokens. Nothing else in the input is kept.
func readGateInput(ctx context.Context, stdin io.Reader) (session, call string, err error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(io.LimitReader(stdin, gateMaxInput+1))
		ch <- result{data, err}
	}()

	var data []byte
	timer := time.NewTimer(gateTimes.stdin)
	defer timer.Stop()
	select {
	case r := <-ch:
		if r.err != nil {
			return "", "", r.err
		}
		data = r.data
	case <-timer.C:
		return "", "", errors.New("stdin read timed out")
	case <-ctx.Done():
		return "", "", ctx.Err()
	}
	if len(data) > gateMaxInput {
		return "", "", errors.New("hook input too large")
	}

	var in struct {
		SessionID string `json:"session_id"`
		ToolUseID string `json:"tool_use_id"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return "", "", err
	}
	if !monitor.ValidSession(in.SessionID) || !monitor.ValidCall(in.ToolUseID) {
		return "", "", errors.New("missing or malformed session_id or tool_use_id")
	}
	return in.SessionID, in.ToolUseID, nil
}

func deny(reason monitor.Reason) monitor.DecideResponse {
	return monitor.DecideResponse{Version: monitor.Version, Decision: monitor.Deny, Reason: reason}
}

// gateHints explains a deny to the model and the person reading along.
var gateHints = map[monitor.Reason]string{
	monitor.ReasonUnregistered:       "the barmkin shim plugin did not register this tool call",
	monitor.ReasonExpired:            "the barmkin shim registration for this tool call expired",
	monitor.ReasonMonitorUnavailable: "the barmkin monitor is not configured or not reachable",
	monitor.ReasonMalformedRequest:   "the hook input or gate configuration is malformed",
	monitor.ReasonMalformedResponse:  "the barmkin monitor sent a malformed reply",
	monitor.ReasonDeadlineExceeded:   "the barmkin gate ran out of time",
}

func writeGateDeny(w io.Writer, resp monitor.DecideResponse) {
	hint := gateHints[resp.Reason]
	if hint == "" {
		hint = "the barmkin monitor denied this tool call"
	}
	out, _ := json.Marshal(resp)
	fmt.Fprintf(w, "[barmkin] gate denied: %s %s\n", hint, out)
}
