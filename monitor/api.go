// Package monitor is the local barmkin monitor: a small, content-free
// decision service reached over HTTP/JSON on a Unix socket.
//
// The contract is versioned by path prefix (/v1/) and by an explicit
// "version" field in every request and response body. It carries no
// tool content - only opaque session and tool-call tokens and values from
// closed enums - so the monitor never sees commands, file contents, or
// prompts.
//
// Every failure path is conservative: a malformed, unknown, unsupported,
// or unanswerable request yields a deny, and a client that cannot reach
// the monitor treats the result as a deny.
//
// Endpoints (v1):
//
//	POST /v1/decide    DecideRequest   -> DecideResponse
//	POST /v1/taint     TaintRequest    -> TaintResponse
//	POST /v1/register  RegisterRequest -> RegisterResponse
//	POST /v1/presence  PresenceRequest -> DecideResponse
package monitor

import (
	"regexp"
	"time"
)

// Version is the only contract version this package speaks.
const Version = 1

// Paths of the v1 endpoints.
const (
	PathDecide   = "/v1/decide"
	PathTaint    = "/v1/taint"
	PathRegister = "/v1/register"
	PathPresence = "/v1/presence"
)

// MaxBodyBytes bounds every request body. Requests are a few dozen bytes;
// anything larger is malformed by construction.
const MaxBodyBytes = 4096

// Operation classifies the action a caller wants a decision for.
type Operation string

const (
	// OpRoutine is an action that stays allowed even in a tainted session.
	OpRoutine Operation = "routine"
	// OpProtected is an action that is denied once the session is tainted.
	OpProtected Operation = "protected"
)

// TaintSource names why a session was tainted.
type TaintSource string

const (
	// SourceUntrustedInput marks a session that has ingested untrusted input.
	SourceUntrustedInput TaintSource = "untrusted-input"
)

// Decision is the monitor's verdict.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

// Reason is a machine-readable code explaining a decision or error.
type Reason string

const (
	ReasonOK                 Reason = "ok"
	ReasonTainted            Reason = "tainted"
	ReasonMalformedRequest   Reason = "malformed-request"
	ReasonUnsupportedVersion Reason = "unsupported-version"
	ReasonUnknownOperation   Reason = "unknown-operation"
	ReasonUnknownSource      Reason = "unknown-source"
	ReasonUnknownEndpoint    Reason = "unknown-endpoint"
	ReasonJournalFailure     Reason = "journal-failure"
	ReasonUnregistered       Reason = "unregistered"
	ReasonExpired            Reason = "expired"
	ReasonCapacityExceeded   Reason = "capacity-exceeded"
	// ReasonMonitorUnavailable, ReasonMalformedResponse and
	// ReasonDeadlineExceeded are produced by clients, never by the server.
	ReasonMonitorUnavailable Reason = "monitor-unavailable"
	ReasonMalformedResponse  Reason = "malformed-response"
	ReasonDeadlineExceeded   Reason = "deadline-exceeded"
)

// DecideRequest asks whether an operation may proceed in a session.
type DecideRequest struct {
	Version   int       `json:"version"`
	Session   string    `json:"session"`
	Operation Operation `json:"operation"`
}

// DecideResponse is the monitor's answer to a DecideRequest. Any response
// that is not exactly a well-formed allow must be treated as a deny.
type DecideResponse struct {
	Version  int      `json:"version"`
	Decision Decision `json:"decision"`
	Reason   Reason   `json:"reason"`
}

// TaintRequest marks a session as tainted. Taint is durable: it is
// journaled and fsynced before the monitor acknowledges it.
type TaintRequest struct {
	Version int         `json:"version"`
	Session string      `json:"session"`
	Source  TaintSource `json:"source"`
}

// TaintResponse acknowledges a TaintRequest. Tainted is true only when the
// taint is durably recorded.
type TaintResponse struct {
	Version int    `json:"version"`
	Tainted bool   `json:"tainted"`
	Reason  Reason `json:"reason"`
}

// RegisterRequest records that a shim saw one tool call. The call token
// is the agent's own opaque tool-call id; nothing about the call itself is
// sent. A registration is held in memory only and lives for PresenceTTL.
type RegisterRequest struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Call    string `json:"call"`
}

// RegisterResponse acknowledges a RegisterRequest. Registered is true only
// when the call is now live.
type RegisterResponse struct {
	Version    int    `json:"version"`
	Registered bool   `json:"registered"`
	Reason     Reason `json:"reason"`
}

// PresenceRequest asks whether a shim registered this call. It is answered
// with a DecideResponse: allow only for a live registration, which the
// answer consumes, so each registration admits exactly one call.
type PresenceRequest struct {
	Version int    `json:"version"`
	Session string `json:"session"`
	Call    string `json:"call"`
}

// PresenceTTL is how long a registration stays live by default. The shim
// registers a call moments before the gate asks about it.
const PresenceTTL = 10 * time.Second

// MaxPresence bounds the live registrations a monitor holds.
const MaxPresence = 4096

// sessionPattern keeps session tokens opaque and content-free: short,
// printable, and with no room to smuggle tool content.
var sessionPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// ValidSession reports whether s is an acceptable session token.
func ValidSession(s string) bool { return sessionPattern.MatchString(s) }

// ValidCall reports whether s is an acceptable tool-call token. Call
// tokens follow the same opaque, content-free shape as session tokens.
func ValidCall(s string) bool { return sessionPattern.MatchString(s) }

func (o Operation) known() bool { return o == OpRoutine || o == OpProtected }

func (s TaintSource) known() bool { return s == SourceUntrustedInput }
