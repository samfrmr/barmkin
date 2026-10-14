// Gate is the managed Claude Code PreToolUse check for shim presence: the
// strict presence gate (G-a) of the barmkin successor.
//
// A managed-settings PreToolUse hook runs `barmkin gate` on every tool
// call. The barmkin shim plugin, a hooks module, registers its session with
// the barmkin monitor (`barmkin monitor`) at session start and pre-registers
// each call (the internal/proto preregister operation) as the model's
// tool_use block is appended to the conversation, before the call starts.
// The gate asks the monitor whether that pre-registration is live (the gate
// operation) and allows the call only if it is: the session is one the
// monitor registered and its shim is live for this very call. The shim then
// makes the call's guard decision. So a session whose shim is missing,
// disabled, unloaded or broken cannot run any tool, egress-capable or not,
// and the deny says the barmkin shim is not present.
//
// Both requests are versioned and content-free: they carry only Claude
// Code's session_id and tool_use_id, never the tool name or input.
//
// The gate exits 0 to allow and 2 to deny. Every failure denies: missing
// configuration, malformed hook input, a call that was never
// pre-registered or whose pre-registration expired or was already used, a
// session the monitor does not know, a malformed monitor reply or one from
// another contract version, an unreachable monitor or one served by a uid
// other than the pinned one (-monitor-uid), and a gate that runs out of
// time. Claude Code treats any other exit code, and a hook timeout,
// as a non-blocking error that lets the call proceed, so the gate never
// exits with another code and always finishes well before the hook
// timeout.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Daviey/barmkin/internal/client"
	"github.com/Daviey/barmkin/internal/proto"
)

// gateTiming bounds every stage of the gate. deadline is the hard limit
// for the whole process and must stay well below the Claude Code hook
// timeout (10s in the managed-settings recipe).
type gateTiming struct {
	deadline time.Duration // whole gate, enforced by a backstop exit
	stdin    time.Duration // reading the hook input
	wait     time.Duration // waiting for the shim's pre-registration to land
	request  time.Duration // each monitor request
	poll     time.Duration // between gate checks while waiting
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

// gateReason is why the gate decided what it did.
type gateReason string

const (
	gateAllowed            gateReason = "preregistered"
	gateUnregistered       gateReason = "unregistered"
	gateUnknownSession     gateReason = "unknown-session"
	gateMonitorUnavailable gateReason = "monitor-unavailable"
	gateVersionMismatch    gateReason = "version-mismatch"
	gateMalformedRequest   gateReason = "malformed-request"
	gateMalformedResponse  gateReason = "malformed-response"
	gateMonitorUIDMismatch gateReason = "monitor-uid-mismatch"
	gateDeadlineExceeded   gateReason = "deadline-exceeded"
)

// gateVerdict is what the gate decided, as it reports a deny on stderr.
type gateVerdict struct {
	Version  int        `json:"version"`
	Decision string     `json:"decision"`
	Reason   gateReason `json:"reason"`
}

func (v gateVerdict) allowed() bool { return v.Decision == "allow" }

func allow() gateVerdict {
	return gateVerdict{Version: proto.Version, Decision: "allow", Reason: gateAllowed}
}

func deny(reason gateReason) gateVerdict {
	return gateVerdict{Version: proto.Version, Decision: "deny", Reason: reason}
}

// cmdGate runs the gate as a process and exits 0 or 2, never anything
// else: a panic or an overrun of the deadline also denies.
func cmdGate(args []string) {
	var once sync.Once
	exit := func(code int) { once.Do(func() { os.Exit(code) }) }

	backstop := time.AfterFunc(gateTimes.deadline, func() {
		once.Do(func() {
			writeGateDeny(os.Stderr, deny(gateDeadlineExceeded))
			os.Exit(2)
		})
	})
	defer backstop.Stop()
	defer func() {
		if recover() != nil {
			once.Do(func() {
				writeGateDeny(os.Stderr, deny(gateMalformedRequest))
				os.Exit(2)
			})
		}
	}()

	exit(runGate(args, os.Stdin, os.Stderr, os.Getenv))
}

// runGate checks one Claude Code PreToolUse call and returns 0 (allow) or
// 2 (deny). On deny it writes the reason and the verdict to stderr, which
// Claude Code shows to the model.
func runGate(args []string, stdin io.Reader, stderr io.Writer, getenv func(string) string) int {
	start := time.Now()
	ctx, cancel := context.WithDeadline(context.Background(), start.Add(gateTimes.deadline))
	defer cancel()

	verdict := gateDecide(ctx, start, args, stdin, getenv)
	if verdict.allowed() {
		return 0
	}
	writeGateDeny(stderr, verdict)
	return 2
}

func gateDecide(ctx context.Context, start time.Time, args []string, stdin io.Reader, getenv func(string) string) gateVerdict {
	fs := flag.NewFlagSet("gate", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	socket := fs.String("socket", getenv(envMonitorSocket), "monitor Unix socket path")
	pin := fs.String("monitor-uid", "", "numeric uid the monitor must run as (checked with SO_PEERCRED)")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return deny(gateMalformedRequest)
	}
	if *socket == "" {
		return deny(gateMonitorUnavailable)
	}
	c := client.Client{Socket: *socket, Timeout: gateTimes.request}
	if *pin != "" {
		uid, err := strconv.ParseUint(*pin, 10, 32)
		if err != nil {
			return deny(gateMalformedRequest)
		}
		c.PeerUID = new(uint32(uid))
	}

	session, call, err := readGateInput(ctx, stdin)
	if err != nil {
		return deny(gateMalformedRequest)
	}

	// The shim pre-registers the call before Claude Code starts it, but its
	// request can still be in flight when the gate starts. Keep asking
	// while the answer is "not pre-registered" and the wait lasts; every
	// other answer is final. A "not pre-registered" answer consumes
	// nothing, so asking again is safe.
	waitUntil := start.Add(gateTimes.wait)
	for {
		verdict := askGate(ctx, c, session, call)
		if verdict.Reason != gateUnregistered {
			return verdict
		}
		if time.Now().Add(gateTimes.poll).After(waitUntil) {
			return verdict
		}
		select {
		case <-ctx.Done():
			return deny(gateDeadlineExceeded)
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
	// Encoding the gate request checks both tokens the way the monitor
	// does, so a malformed one is never sent.
	if _, err := proto.Encode(gateRequest(in.SessionID, in.ToolUseID)); err != nil {
		return "", "", errors.New("missing or malformed session_id or tool_use_id")
	}
	return in.SessionID, in.ToolUseID, nil
}

func gateRequest(session, call string) *proto.GateRequest {
	return &proto.GateRequest{Version: proto.Version, Host: proto.HostClaudeCode, Session: session, Call: call}
}

// askGate asks the monitor whether call was pre-registered. Only a
// well-formed GateResponse that says so allows; everything else denies.
func askGate(ctx context.Context, c client.Client, session, call string) gateVerdict {
	var g proto.GateResponse
	err := c.Do(ctx, proto.OpGate, gateRequest(session, call), &g)
	switch {
	case err == nil && g.Preregistered:
		return allow()
	case err == nil:
		return deny(gateUnregistered)
	case ctx.Err() != nil:
		return deny(gateDeadlineExceeded)
	case errors.Is(err, client.ErrPeer):
		return deny(gateMonitorUIDMismatch)
	case errors.Is(err, client.ErrMalformed):
		return deny(gateMalformedResponse)
	}
	if pe, ok := errors.AsType[*proto.Error](err); ok {
		return deny(codeReason(pe.Code))
	}
	return deny(gateMonitorUnavailable)
}

// codeReason is the reason for an error code the monitor answered with.
func codeReason(code proto.Code) gateReason {
	switch code {
	case proto.CodeUnknownSession:
		return gateUnknownSession
	case proto.CodeVersionMismatch:
		return gateVersionMismatch
	case proto.CodeBadRequest:
		return gateMalformedRequest
	default:
		return gateMonitorUnavailable
	}
}

// gateHints explains a deny to the model and the person reading along.
var gateHints = map[gateReason]string{
	gateUnregistered:       "barmkin shim not present: the barmkin shim plugin did not pre-register this tool call, or its pre-registration expired or was already used",
	gateUnknownSession:     "barmkin shim not present: the barmkin monitor does not know this session, so the barmkin shim plugin has not registered it",
	gateMonitorUIDMismatch: "the barmkin monitor socket is served by a process that does not run as the pinned monitor uid",
	gateMonitorUnavailable: "the barmkin monitor is not configured, not reachable, or cannot answer safely",
	gateVersionMismatch:    "the barmkin monitor speaks another contract version; upgrade the gate, shim and monitor together",
	gateMalformedRequest:   "the hook input or gate configuration is malformed",
	gateMalformedResponse:  "the barmkin monitor sent a malformed reply",
	gateDeadlineExceeded:   "the barmkin gate ran out of time",
}

func writeGateDeny(w io.Writer, verdict gateVerdict) {
	hint := gateHints[verdict.Reason]
	if hint == "" {
		hint = "the barmkin monitor denied this tool call"
	}
	out, _ := json.Marshal(verdict)
	fmt.Fprintf(w, "[barmkin] gate denied: %s %s\n", hint, out)
}
