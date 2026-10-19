// Package admin is the wire contract of the barmkin monitor's opt-in
// administrative socket, through which root lists lineages and clears one.
//
// It is separate from internal/proto, the contract every shim speaks: no
// shim, plugin, MCP server or managed gate uses it, and the monitor's client
// socket answers none of its paths. The default deployment has no
// administrative socket, so its taint is sticky: legs only rise.
//
// # Transport
//
// Each operation is an HTTP POST of one JSON object to /admin/v1/<op> on
// the administrative socket. systemd, as root, creates that socket in a
// root-only directory (barmkin-monitor-admin.socket) and passes it to the
// monitor, which serves it only when started with -admin-socket. The
// monitor reads every connection's peer credentials and closes any
// connection not from root before it reads a byte; a request that still
// reaches it from another uid fails forbidden.
//
//	list   ListRequest   -> ListResponse
//	clear  ClearRequest  -> ClearResponse
//
// # Content
//
// Every message is content-free: lineages and sessions are opaque tokens,
// uids are numbers, times are Unix seconds, and everything else, the clear
// reason included, comes from a closed set. Nothing a tool call carried is
// ever listed.
//
// # Clearing
//
// clear names one lineage exactly (uid, host and root token), with the
// epoch and legs the operator was shown and a closed reason. The monitor
// refuses it with not_found when no such lineage exists (a subagent's
// session token names no lineage), and with mismatch when the lineage's
// epoch or legs are no longer the ones shown. Otherwise it appends a clear
// record that starts the next epoch, fsyncs it, and only then lowers both
// legs and answers. The records of the raises it cleared stay in the
// journal and in list. Every pre-registration of the lineage's sessions is
// dropped, and each session must register again before the monitor answers
// anything else it asks.
//
// Clearing monitor state does not remove untrusted material already in an
// AI conversation. A prompt injection the session read is still in its
// context after a clear, and nothing in the monitor can take it out.
package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// Version is the only administrative contract version.
const Version = 1

// PathPrefix starts the path of every administrative operation. It never
// overlaps proto.PathPrefix.
const PathPrefix = "/admin/v1/"

// MaxRequestBytes bounds a request body; MaxResponseBytes bounds a list,
// which names every session the monitor holds.
const (
	MaxRequestBytes  = 8 << 10
	MaxResponseBytes = 64 << 20
)

// Op names an administrative operation.
type Op string

const (
	OpList  Op = "list"
	OpClear Op = "clear"
)

// Ops lists every administrative operation.
var Ops = []Op{OpList, OpClear}

// Path is the HTTP path of the operation.
func (o Op) Path() string { return PathPrefix + string(o) }

// ParsePath returns the operation a request path names, matching exact
// paths only.
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
	// CodeForbidden: the request did not come from root.
	CodeForbidden Code = "forbidden"
	// CodeNotFound: no lineage has that uid, host and root token.
	CodeNotFound Code = "not_found"
	// CodeMismatch: the lineage's epoch or legs are not the ones named.
	CodeMismatch Code = "mismatch"
	// CodeUnavailable: the monitor cannot change its state safely.
	CodeUnavailable Code = "unavailable"
)

// Codes lists every error code.
var Codes = []Code{CodeBadRequest, CodeForbidden, CodeNotFound, CodeMismatch, CodeUnavailable}

// HTTPStatus is the status sent with an ErrorResponse carrying c.
func (c Code) HTTPStatus() int {
	switch c {
	case CodeBadRequest:
		return http.StatusBadRequest
	case CodeForbidden:
		return http.StatusForbidden
	case CodeNotFound:
		return http.StatusNotFound
	case CodeMismatch:
		return http.StatusConflict
	default:
		return http.StatusServiceUnavailable
	}
}

// Error is a failed request, carrying only its code.
type Error struct{ Code Code }

func (e *Error) Error() string { return "barmkin admin: " + string(e.Code) }

// Message is one of this package's request or response types.
type Message interface{ validate() error }

// ListRequest asks for every lineage.
type ListRequest struct {
	Version int `json:"version"`
}

// ListResponse holds every lineage, sorted by uid, host and lineage.
type ListResponse struct {
	Version  int       `json:"version"`
	Lineages []Lineage `json:"lineages"`
}

// Lineage is one root lineage's state and history.
type Lineage struct {
	UID         uint32     `json:"uid"`
	Host        proto.Host `json:"host"`
	Lineage     string     `json:"lineage"` // the root session's token
	Epoch       uint64     `json:"epoch"`   // 0 until the first clear
	Legs        proto.Legs `json:"legs"`
	UntrustedAt int64      `json:"untrusted_at"` // Unix seconds; 0 while down or unknown
	SensitiveAt int64      `json:"sensitive_at"`
	Sessions    []Session  `json:"sessions"`
	Clears      []Clear    `json:"clears"` // oldest first
}

// Session is one session of a lineage.
type Session struct {
	Session string `json:"session"`
	// Current is false for a session registered before the lineage's last
	// clear, which must register again before it is answered.
	Current bool  `json:"current"`
	At      int64 `json:"at"` // Unix seconds it last registered; 0 when unknown
}

// Clear is one past clear and the legs it lowered.
type Clear struct {
	Epoch       uint64         `json:"epoch"` // the epoch it began
	Reason      journal.Reason `json:"reason"`
	At          int64          `json:"at"`
	Legs        proto.Legs     `json:"legs"` // the legs it lowered
	UntrustedAt int64          `json:"untrusted_at"`
	SensitiveAt int64          `json:"sensitive_at"`
}

// ClearRequest clears one lineage, named exactly, whose epoch and legs must
// still be Epoch and Legs.
type ClearRequest struct {
	Version int            `json:"version"`
	UID     uint32         `json:"uid"`
	Host    proto.Host     `json:"host"`
	Lineage string         `json:"lineage"`
	Epoch   uint64         `json:"epoch"`
	Legs    proto.Legs     `json:"legs"`
	Reason  journal.Reason `json:"reason"`
}

// ClearResponse is the lineage after the clear was journaled.
type ClearResponse struct {
	Version int     `json:"version"`
	Lineage Lineage `json:"lineage"`
}

// ErrorResponse is the body of every failed request.
type ErrorResponse struct {
	Version int  `json:"version"`
	Error   Code `json:"error"`
}

var errInvalid = errors.New("invalid admin message")

func check(ok bool) error {
	if !ok {
		return errInvalid
	}
	return nil
}

// ValidHost reports whether h is a host the monitor serves.
func ValidHost(h proto.Host) bool { return h == proto.HostClaudeCode || h == proto.HostOpenCode }

func validLeg(leg journal.Leg, s proto.Source) bool {
	return s == proto.SourceNone || journal.SourceFits(leg, s)
}

// ValidLegs reports whether l holds only sources its legs can hold.
func ValidLegs(l proto.Legs) bool {
	return validLeg(journal.LegUntrusted, l.Untrusted) && validLeg(journal.LegSensitive, l.Sensitive)
}

func (m *ListRequest) validate() error { return check(m.Version == Version) }

func (m *ListResponse) validate() error {
	if m.Version != Version || m.Lineages == nil {
		return errInvalid
	}
	for i := range m.Lineages {
		if err := m.Lineages[i].validate(); err != nil {
			return err
		}
	}
	return nil
}

func (l *Lineage) validate() error {
	if !ValidHost(l.Host) || !proto.ValidToken(l.Lineage) || !ValidLegs(l.Legs) || l.Sessions == nil || l.Clears == nil {
		return errInvalid
	}
	for _, s := range l.Sessions {
		if !proto.ValidToken(s.Session) {
			return errInvalid
		}
	}
	for _, c := range l.Clears {
		if !journal.ValidReason(c.Reason) || !ValidLegs(c.Legs) {
			return errInvalid
		}
	}
	return nil
}

func (m *ClearRequest) validate() error {
	return check(m.Version == Version && ValidHost(m.Host) && proto.ValidToken(m.Lineage) &&
		ValidLegs(m.Legs) && journal.ValidReason(m.Reason))
}

func (m *ClearResponse) validate() error {
	if m.Version != Version {
		return errInvalid
	}
	return m.Lineage.validate()
}

func (m *ErrorResponse) validate() error {
	return check(m.Version == Version && slices.Contains(Codes, m.Error))
}

// NewRequest returns a new, empty request for op.
func NewRequest(op Op) Message {
	switch op {
	case OpList:
		return &ListRequest{}
	case OpClear:
		return &ClearRequest{}
	}
	return nil
}

// Decode strictly decodes one message of at most limit bytes into m: one
// JSON object, every field present, no unknown or null field, and a valid
// message. It fails with a bad_request *Error.
func Decode(data []byte, limit int, m Message) error {
	bad := &Error{Code: CodeBadRequest}
	if len(data) > limit || !json.Valid(data) {
		return bad
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || !complete(fields, m) {
		return bad
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if dec.Decode(m) != nil || dec.More() || m.validate() != nil {
		return bad
	}
	return nil
}

// complete reports whether fields has every top-level field of m, and no
// null.
func complete(fields map[string]json.RawMessage, m Message) bool {
	full, err := json.Marshal(m)
	if err != nil {
		return false
	}
	var want map[string]json.RawMessage
	if json.Unmarshal(full, &want) != nil {
		return false
	}
	for k := range want {
		v, ok := fields[k]
		if !ok || string(v) == "null" {
			return false
		}
	}
	return len(fields) == len(want)
}

// Encode validates m and returns its wire form.
func Encode(m Message) ([]byte, error) {
	if m.validate() != nil {
		return nil, &Error{Code: CodeBadRequest}
	}
	return json.Marshal(m)
}
