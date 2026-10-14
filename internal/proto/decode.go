package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"slices"
	"strings"
	"unicode/utf16"
)

// Message is one of this package's request or response types.
type Message interface {
	validate() error
}

// errInvalid marks a failed check; Decode and Encode report it as bad_request.
var errInvalid = errors.New("invalid message")

func badRequest() error { return &Error{Code: CodeBadRequest} }

// Decode strictly decodes one message body into m, which must be a pointer
// to one of this package's types. It fails with an *Error: version_mismatch
// when the body carries an integer version other than Version, and
// bad_request for anything else that is not a valid message.
func Decode(data []byte, m Message) error {
	if len(data) > MaxBodyBytes || !json.Valid(data) {
		return badRequest()
	}
	// The version is checked before the rest of the shape, so a message
	// from another version is a mismatch even if its fields differ.
	var peek map[string]json.RawMessage
	var v *float64 // stays nil for null
	if json.Unmarshal(data, &peek) == nil && json.Unmarshal(peek["version"], &v) == nil &&
		v != nil && *v == math.Trunc(*v) && *v != Version {
		return &Error{Code: CodeVersionMismatch}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if checkShape(dec, reflect.TypeOf(m).Elem()) != nil {
		return badRequest()
	}
	if json.Unmarshal(data, m) != nil || m.validate() != nil {
		return badRequest()
	}
	return nil
}

// Encode validates m and returns its wire form. It fails with a
// bad_request *Error rather than send an invalid message.
func Encode(m Message) ([]byte, error) {
	if m.validate() != nil {
		return nil, badRequest()
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false) // match JSON.stringify
	if err := enc.Encode(m); err != nil {
		return nil, badRequest()
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// checkShape reads one JSON value from dec and checks it against t: objects
// must hold exactly t's fields, each once and spelled exactly as its tag;
// arrays, strings, booleans and numbers must appear where t has them; null
// appears nowhere. encoding/json alone would match keys case-insensitively,
// keep the last of a repeated key, and accept null or missing fields.
func checkShape(dec *json.Decoder, t reflect.Type) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	ok := false
	switch t.Kind() {
	case reflect.Struct:
		if tok != json.Delim('{') {
			break
		}
		fields := map[string]reflect.Type{}
		for f := range t.Fields() {
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			fields[name] = f.Type
		}
		seen := map[string]bool{}
		for dec.More() {
			tok, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := tok.(string)
			ft, known := fields[key]
			if !known || seen[key] {
				return errInvalid
			}
			seen[key] = true
			if err := checkShape(dec, ft); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		ok = len(seen) == len(fields)
	case reflect.Slice:
		if tok != json.Delim('[') {
			break
		}
		for dec.More() {
			if err := checkShape(dec, t.Elem()); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		ok = true
	case reflect.String:
		_, ok = tok.(string)
	case reflect.Bool:
		_, ok = tok.(bool)
	case reflect.Int, reflect.Float64:
		_, ok = tok.(json.Number)
	}
	if !ok {
		return errInvalid
	}
	return nil
}

// MaxTokenBytes bounds a session, root or call token.
const MaxTokenBytes = 128

// ValidToken reports whether s is an opaque session, root or call token:
// 1 to MaxTokenBytes ASCII letters, digits, '.', '_' or '-'. Keeping tokens
// to this shape keeps them content-free. It is checked byte by byte rather
// than with a regexp, which would cost every process that links this
// package (the managed gate among them) a compile at start.
func ValidToken(s string) bool {
	if len(s) == 0 || len(s) > MaxTokenBytes {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9', c == '.', c == '_', c == '-':
		default:
			return false
		}
	}
	return true
}

func check(conds ...bool) error {
	for _, c := range conds {
		if !c {
			return errInvalid
		}
	}
	return nil
}

func oneOf[T comparable](v T, set ...T) bool { return slices.Contains(set, v) }

func (h Host) valid() bool { return oneOf(h, HostClaudeCode, HostOpenCode) }

// untrustedFromShim reports whether a shim may report s for the untrusted leg.
func (s Source) untrustedFromShim() bool {
	return oneOf(s, SourceMCP, SourceFetch, SourceRead, SourcePeer, SourceSkill, SourceInvisible)
}

func (l Legs) valid() bool {
	untrusted := l.Untrusted == SourceNone || l.Untrusted.untrustedFromShim() ||
		oneOf(l.Untrusted, SourceUnknownSession, SourceMonitorRestart)
	return untrusted && oneOf(l.Sensitive, SourceNone, SourceCredential)
}

func (c Class) valid() bool {
	return oneOf(c, ClassShellOutward, ClassNetClient, ClassDNS, ClassForge, ClassPublish,
		ClassCloud, ClassInterpreterNet, ClassPersistShell, ClassDestructive, ClassHistoryRewrite,
		ClassWebFetch, ClassWebSearch, ClassMonitorWS, ClassMCPWrite, ClassSkillLoad, ClassPersistence)
}

// validClasses requires a non-nil list of known classes with no repeats.
func validClasses(cs []Class) bool {
	if cs == nil {
		return false
	}
	seen := map[Class]bool{}
	for _, c := range cs {
		if !c.valid() || seen[c] {
			return false
		}
		seen[c] = true
	}
	return true
}

func (s Scores) valid() bool {
	for _, p := range []float64{s.Injection, s.Credentials, s.Exfiltration} {
		if !(p >= 0 && p <= 1) {
			return false
		}
	}
	return true
}

func validWindows(ws []string) bool {
	if len(ws) == 0 || len(ws) > MaxWindows {
		return false
	}
	for _, w := range ws {
		if n := len(utf16.Encode([]rune(w))); n == 0 || n > MaxWindowSize {
			return false
		}
	}
	return true
}

// scoped checks the fields every session-scoped request shares.
func scoped(version int, host Host, session string) bool {
	return version == Version && host.valid() && ValidToken(session)
}

func (m *RegisterRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session), ValidToken(m.Root))
}

func (m *RegisterResponse) validate() error {
	return check(m.Version == Version, m.Legs.valid())
}

func (m *PreregisterRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session), ValidToken(m.Call))
}

func (m *PreregisterResponse) validate() error {
	return check(m.Version == Version, m.TTLMS > 0)
}

func (m *GateRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session), ValidToken(m.Call))
}

func (m *GateResponse) validate() error { return check(m.Version == Version) }

func (m *DecideRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session), validClasses(m.Classes))
}

func (m *DecideResponse) validate() error {
	var consistent bool
	switch m.Verdict {
	case VerdictPass:
		consistent = m.Rule == RuleNone && len(m.Classes) == 0
	case VerdictWarn:
		consistent = len(m.Classes) > 0
	case VerdictDeny:
		consistent = m.Rule != RuleNone && len(m.Classes) > 0
	}
	return check(m.Version == Version, consistent,
		oneOf(m.Rule, RuleNone, RuleUntrusted, RuleRuleOfTwo),
		validClasses(m.Classes), m.Legs.valid())
}

func (m *ScreenRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session), m.Source.untrustedFromShim(),
		validWindows(m.Windows), m.Scores.valid())
}

func (m *ScreenResponse) validate() error {
	return check(m.Version == Version,
		oneOf(m.Decision, ScreenPass, ScreenEscalate, ScreenDeny),
		m.Scores.valid(), oneOf(m.Gap, GapNone, GapScanLimit, GapUnclassified), m.Legs.valid())
}

func (m *ObserveRequest) validate() error {
	return check(scoped(m.Version, m.Host, m.Session),
		m.Source.untrustedFromShim() || m.Source == SourceCredential)
}

func (m *ObserveResponse) validate() error {
	return check(m.Version == Version, m.Legs.valid())
}

func (m *StatusRequest) validate() error { return check(scoped(m.Version, m.Host, m.Session)) }

func (m *StatusResponse) validate() error {
	return check(m.Version == Version, m.Legs.valid(),
		oneOf(m.Classifier, ClassifierOK, ClassifierDegraded))
}

func (m *HealthRequest) validate() error { return check(m.Version == Version) }

func (m *HealthResponse) validate() error {
	return check(m.Version == Version, oneOf(m.State, HealthOK, HealthDegraded))
}

func (m *ErrorResponse) validate() error {
	return check(m.Version == Version, oneOf(m.Error, Codes...))
}
