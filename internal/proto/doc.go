// Package proto is the versioned wire contract between barmkin's host shims
// and the barmkin monitor. It defines the request and response types, the
// closed vocabularies they use, the error codes, and strict decoding. It
// holds no monitor logic: sessions, leg decisions, screening and the
// journal belong to the monitor.
//
// # Transport
//
// Each operation is an HTTP POST of one JSON object to /v1/<op> on the
// monitor's Unix socket (for example $XDG_RUNTIME_DIR/barmkin/monitor.sock
// or /run/barmkin/monitor.sock). It is the one binding every host can
// reach: a Claude Code mod through $.http.fetch with socketPath, an
// OpenCode plugin, and a Go command hook. There is no other transport.
//
// A success is HTTP 200 with the operation's response. A failure is the
// HTTP status of its code (see [Code.HTTPStatus]) with an [ErrorResponse].
// A request to a path that names no operation, or with another method,
// fails with [CodeBadRequest].
//
// # Operations
//
//	register     RegisterRequest     -> RegisterResponse
//	preregister  PreregisterRequest  -> PreregisterResponse
//	gate         GateRequest         -> GateResponse
//	decide       DecideRequest       -> DecideResponse
//	screen       ScreenRequest       -> ScreenResponse
//	observe      ObserveRequest      -> ObserveResponse
//	status       StatusRequest       -> StatusResponse
//	health       HealthRequest       -> HealthResponse
//
// A shim registers its session, pre-registers each tool call by its
// tool_use_id before the host's managed gate runs, asks decide for each
// egress-capable call, sends untrusted content to screen, reports other leg
// raises through observe, and reads status for its display. The managed
// gate client asks gate whether a call was pre-registered. health needs no
// session.
//
// # Sticky taint
//
// A session has two legs: untrusted (leg A, untrusted input was ingested)
// and sensitive (leg B, sensitive data was touched). Legs only rise, and
// nothing in this contract lowers one: there is no clear or rotate
// operation, no clear capability, and no human-prompt rotation. A session
// keeps its legs until it ends; a new session is a new registration.
//
// # Versioning and decoding
//
// Every request and response carries "version", which must equal
// [Version]. A message with any other integer version fails with
// [CodeVersionMismatch] before anything else in it is checked, so a shim
// and monitor of different versions always learn that they disagree. A
// shim that sees a version mismatch denies guarded calls.
//
// Decoding is strict on both sides, and the Go and TypeScript decoders
// agree on the shared fixtures in testdata:
//   - the body is exactly one JSON object of at most [MaxBodyBytes] bytes;
//   - every field is required, keys match case-sensitively, and an unknown
//     or repeated key is rejected;
//   - no value is null, and arrays are never omitted, only empty;
//   - enumerated values come from the closed sets in this package.
//
// # Content
//
// Every message is content-free except a screen request: sessions and
// calls are opaque tokens, and everything else is a value from a closed
// set. Errors are codes with no free text. A screen request carries the
// shim's already-redacted classifier windows, which the monitor scores and
// never journals or echoes back. Prose shown to a user stays in the shim.
//
// # Deadlines and failure
//
// Clients bound each request by [ClientDeadline]. A shim treats a timeout,
// a refused connection, a malformed reply, or any error code as a deny of
// the guarded call, and never as an allow. The managed gate client exits 2
// (deny) on any of these, never 0, and its deadline sits below the host's
// hook timeout so it fails closed on its own.
package proto
