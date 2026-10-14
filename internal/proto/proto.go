package proto

import (
	"net/http"
	"strings"
	"time"
)

// Version is the only contract version this package speaks.
const Version = 1

// PathPrefix starts the path of every operation in this version.
const PathPrefix = "/v1/"

// MaxBodyBytes bounds every request and response body. The largest message
// is a screen request carrying MaxWindows windows.
const MaxBodyBytes = 128 << 10

// ClientDeadline bounds each request a client makes, end to end.
const ClientDeadline = 1000 * time.Millisecond

// Op names an operation. Its path is PathPrefix followed by the name.
type Op string

const (
	OpRegister    Op = "register"
	OpPreregister Op = "preregister"
	OpGate        Op = "gate"
	OpDecide      Op = "decide"
	OpScreen      Op = "screen"
	OpObserve     Op = "observe"
	OpStatus      Op = "status"
	OpHealth      Op = "health"
)

// Ops lists every operation in this version.
var Ops = []Op{OpRegister, OpPreregister, OpGate, OpDecide, OpScreen, OpObserve, OpStatus, OpHealth}

// Path is the HTTP path of the operation.
func (o Op) Path() string { return PathPrefix + string(o) }

// ParsePath returns the operation a request path names. Only exact paths
// match: no trailing slash, query-free, and in this version only.
func ParsePath(path string) (Op, bool) {
	name, ok := strings.CutPrefix(path, PathPrefix)
	if !ok {
		return "", false
	}
	for _, o := range Ops {
		if string(o) == name {
			return o, true
		}
	}
	return "", false
}

// Code is a closed, content-free error code.
type Code string

const (
	// CodeBadRequest: the body, path or method is not a valid request.
	CodeBadRequest Code = "bad_request"
	// CodeVersionMismatch: the message's version is not Version.
	CodeVersionMismatch Code = "version_mismatch"
	// CodeUnknownSession: the session was never registered with this monitor.
	CodeUnknownSession Code = "unknown_session"
	// CodePostureRefused: register was refused because of the reported posture.
	CodePostureRefused Code = "posture_refused"
	// CodeUnavailable: the monitor cannot answer safely right now, or a
	// client could not reach it or read its reply.
	CodeUnavailable Code = "unavailable"
)

// Codes lists every error code.
var Codes = []Code{CodeBadRequest, CodeVersionMismatch, CodeUnknownSession, CodePostureRefused, CodeUnavailable}

// HTTPStatus is the status a monitor sends with an ErrorResponse carrying c.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeVersionMismatch, CodeBadRequest:
		return http.StatusBadRequest
	case CodeUnknownSession:
		return http.StatusNotFound
	case CodePostureRefused:
		return http.StatusForbidden
	default:
		return http.StatusServiceUnavailable
	}
}

// Error is a failed decode or request, carrying only its code.
type Error struct{ Code Code }

func (e *Error) Error() string { return "barmkin proto: " + string(e.Code) }

// Host names the agent host a shim runs in.
type Host string

const (
	HostClaudeCode Host = "claude_code"
	HostOpenCode   Host = "opencode"
)

// Source names what raised a leg. SourceNone means the leg is down.
type Source string

const (
	SourceNone Source = "none"

	// Untrusted (leg A) sources a shim reports.
	SourceMCP       Source = "mcp"       // an MCP tool result or description
	SourceFetch     Source = "fetch"     // a web fetch or search result
	SourceRead      Source = "read"      // a file read from outside the project
	SourcePeer      Source = "peer"      // a message from another agent
	SourceSkill     Source = "skill"     // a loaded skill
	SourceInvisible Source = "invisible" // content that hid invisible characters

	// SourceCredential is the sensitive (leg B) source a shim reports: a
	// credential path or credential-shaped value was touched.
	SourceCredential Source = "credential"

	// Untrusted (leg A) sources only the monitor sets.
	SourceUnknownSession Source = "unknown_session" // the session's history is not known to be clean
	SourceMonitorRestart Source = "monitor_restart" // the monitor lost the session's state
)

// Class is an egress class id, as the shims classify tool calls.
type Class string

const (
	ClassShellOutward   Class = "shell-outward"
	ClassNetClient      Class = "net-client"
	ClassDNS            Class = "dns"
	ClassForge          Class = "forge"
	ClassPublish        Class = "publish"
	ClassCloud          Class = "cloud"
	ClassInterpreterNet Class = "interpreter-net"
	ClassPersistShell   Class = "persist-shell"
	ClassDestructive    Class = "destructive"
	ClassHistoryRewrite Class = "history-rewrite"
	ClassWebFetch       Class = "web-fetch"
	ClassWebSearch      Class = "web-search"
	ClassMonitorWS      Class = "monitor-ws"
	ClassMCPWrite       Class = "mcp-write"
	ClassSkillLoad      Class = "skill-load"
	ClassPersistence    Class = "persistence"
)

// Verdict is decide's answer for one tool call.
type Verdict string

const (
	VerdictPass Verdict = "pass" // no objection
	VerdictWarn Verdict = "warn" // proceed, and show a warning
	VerdictDeny Verdict = "deny"
)

// Rule names why decide warned or denied.
type Rule string

const (
	RuleNone      Rule = "none"
	RuleUntrusted Rule = "untrusted"   // the untrusted leg is up
	RuleRuleOfTwo Rule = "rule_of_two" // both legs are up
)

// ScreenDecision is screen's answer for one piece of content.
type ScreenDecision string

const (
	ScreenPass     ScreenDecision = "pass"
	ScreenEscalate ScreenDecision = "escalate" // the content raised a leg
	ScreenDeny     ScreenDecision = "deny"     // the content must be withheld
)

// Gap names content the classifier could not score.
type Gap string

const (
	GapNone         Gap = "none"
	GapScanLimit    Gap = "scan_limit"   // content ran past the scanned windows
	GapUnclassified Gap = "unclassified" // a window got no classifier answer
)

// Health is the monitor's overall state.
type Health string

const (
	HealthOK       Health = "ok"
	HealthDegraded Health = "degraded" // it denies until restarted
)

// ClassifierState is the state of the monitor's remote classifier.
type ClassifierState string

const (
	ClassifierOK       ClassifierState = "ok"
	ClassifierDegraded ClassifierState = "degraded" // breaker open or unconfigured; local scores only
)

// Screen request bounds, in UTF-16 code units as the shims measure text.
const (
	MaxWindows    = 5
	MaxWindowSize = 4000
)

// Legs is a session's taint. Each leg is the source that first raised it,
// or SourceNone. Untrusted holds an untrusted source; Sensitive holds
// SourceCredential or SourceNone.
type Legs struct {
	Untrusted Source `json:"untrusted"`
	Sensitive Source `json:"sensitive"`
}

// Posture is the host configuration a shim reports at register.
type Posture struct {
	SandboxEnabled      bool `json:"sandbox_enabled"`
	AllowAllUnixSockets bool `json:"allow_all_unix_sockets"`
}

// Scores are classifier probabilities in [0, 1].
type Scores struct {
	Injection    float64 `json:"injection"`
	Credentials  float64 `json:"credentials"`
	Exfiltration float64 `json:"exfiltration"`
}

// RegisterRequest opens or resumes a session. Fresh is true only when the
// host reports that the session has just started; a session the monitor
// does not know that is not fresh registers with its untrusted leg raised
// by SourceUnknownSession. Registering again never lowers a leg.
type RegisterRequest struct {
	Version int     `json:"version"`
	Host    Host    `json:"host"`
	Session string  `json:"session"`
	Root    string  `json:"root"` // the top-level session; Session itself when top-level
	Fresh   bool    `json:"fresh"`
	Posture Posture `json:"posture"`
}

// RegisterResponse reports the registered session's legs.
type RegisterResponse struct {
	Version int  `json:"version"`
	Legs    Legs `json:"legs"`
}

// PreregisterRequest records that the shim saw tool call Call before the
// host's managed gate asks about it.
type PreregisterRequest struct {
	Version int    `json:"version"`
	Host    Host   `json:"host"`
	Session string `json:"session"`
	Call    string `json:"call"`
}

// PreregisterResponse confirms a pre-registration and how long it lives.
type PreregisterResponse struct {
	Version int `json:"version"`
	TTLMS   int `json:"ttl_ms"`
}

// GateRequest asks whether tool call Call was pre-registered.
type GateRequest struct {
	Version int    `json:"version"`
	Host    Host   `json:"host"`
	Session string `json:"session"`
	Call    string `json:"call"`
}

// GateResponse answers a GateRequest. A true answer consumes the
// pre-registration, so each one admits a single call.
type GateResponse struct {
	Version       int  `json:"version"`
	Preregistered bool `json:"preregistered"`
}

// DecideRequest asks for a verdict on a tool call the shim classified into
// Classes, which may be empty and holds no repeats.
type DecideRequest struct {
	Version int     `json:"version"`
	Host    Host    `json:"host"`
	Session string  `json:"session"`
	Classes []Class `json:"classes"`
}

// DecideResponse is the verdict. A pass names no classes and RuleNone; a
// warn or deny names the classes it applies to, and a deny names its rule.
type DecideResponse struct {
	Version int     `json:"version"`
	Verdict Verdict `json:"verdict"`
	Rule    Rule    `json:"rule"`
	Classes []Class `json:"classes"`
	Legs    Legs    `json:"legs"`
}

// ScreenRequest sends untrusted content for scoring. Windows are the shim's
// already-redacted classifier windows; Scores are its local heuristic
// scores; Source is the untrusted source the content came from.
type ScreenRequest struct {
	Version int      `json:"version"`
	Host    Host     `json:"host"`
	Session string   `json:"session"`
	Source  Source   `json:"source"`
	Windows []string `json:"windows"`
	Scores  Scores   `json:"scores"`
}

// ScreenResponse is the screen's decision, its composed scores, any gap in
// coverage, and the session's legs afterwards.
type ScreenResponse struct {
	Version  int            `json:"version"`
	Decision ScreenDecision `json:"decision"`
	Scores   Scores         `json:"scores"`
	Gap      Gap            `json:"gap"`
	Legs     Legs           `json:"legs"`
}

// ObserveRequest raises the leg Source belongs to, for an event the shim
// detected itself.
type ObserveRequest struct {
	Version int    `json:"version"`
	Host    Host   `json:"host"`
	Session string `json:"session"`
	Source  Source `json:"source"`
}

// ObserveResponse reports the session's legs after the observation.
type ObserveResponse struct {
	Version int  `json:"version"`
	Legs    Legs `json:"legs"`
}

// StatusRequest reads a session's state for display.
type StatusRequest struct {
	Version int    `json:"version"`
	Host    Host   `json:"host"`
	Session string `json:"session"`
}

// StatusResponse is a session's legs and the classifier's state.
type StatusResponse struct {
	Version    int             `json:"version"`
	Legs       Legs            `json:"legs"`
	Classifier ClassifierState `json:"classifier"`
}

// HealthRequest asks whether the monitor can answer safely.
type HealthRequest struct {
	Version int `json:"version"`
}

// HealthResponse is the monitor's overall state.
type HealthResponse struct {
	Version int    `json:"version"`
	State   Health `json:"state"`
}

// ErrorResponse is the body of every failed request.
type ErrorResponse struct {
	Version int  `json:"version"`
	Error   Code `json:"error"`
}

// NewRequest returns a new, empty request for op.
func NewRequest(op Op) (Message, bool) {
	switch op {
	case OpRegister:
		return &RegisterRequest{}, true
	case OpPreregister:
		return &PreregisterRequest{}, true
	case OpGate:
		return &GateRequest{}, true
	case OpDecide:
		return &DecideRequest{}, true
	case OpScreen:
		return &ScreenRequest{}, true
	case OpObserve:
		return &ObserveRequest{}, true
	case OpStatus:
		return &StatusRequest{}, true
	case OpHealth:
		return &HealthRequest{}, true
	}
	return nil, false
}

// NewResponse returns a new, empty success response for op.
func NewResponse(op Op) (Message, bool) {
	switch op {
	case OpRegister:
		return &RegisterResponse{}, true
	case OpPreregister:
		return &PreregisterResponse{}, true
	case OpGate:
		return &GateResponse{}, true
	case OpDecide:
		return &DecideResponse{}, true
	case OpScreen:
		return &ScreenResponse{}, true
	case OpObserve:
		return &ObserveResponse{}, true
	case OpStatus:
		return &StatusResponse{}, true
	case OpHealth:
		return &HealthResponse{}, true
	}
	return nil, false
}
