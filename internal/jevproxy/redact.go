package jevproxy

// Secret wraps a value that must never reach a log line, journal, export
// or diagnostic unredacted: the OpenRouter key, and anything derived from
// it such as the Authorization header. Its only way out is [Secret.Value];
// every formatting path prints "[REDACTED]" instead (empty prints "",
// matching screen.Credential's convention), so passing a Secret to a Logf
// call or an error message (including via %v, %s, %q, %+v and %#v) can
// never leak it, however the value is embedded or wrapped upstream.
type Secret string

const redacted = "[REDACTED]"

// String implements fmt.Stringer.
func (s Secret) String() string {
	if s == "" {
		return ""
	}
	return redacted
}

// GoString implements fmt.GoStringer, guarding %#v.
func (s Secret) GoString() string { return `jevproxy.Secret("` + s.String() + `")` }

// MarshalText guards accidental JSON or text marshaling of a Secret.
func (s Secret) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Value returns the wrapped secret. Call it only to use the value, never
// to log or report it.
func (s Secret) Value() string { return string(s) }
