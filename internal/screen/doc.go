// Package screen is the monitor's Jev screen service: it scores untrusted
// content with the Jev System One classifier and decides pass, escalate or
// deny. It is a Go port of barmkin-mod's public TypeScript screen
// (hooks/lib/system-one-client.ts, jev-questions.ts, classifier-windows.ts,
// taint.ts and the screen step of hooks/register.ts). It holds no session
// state: the monitor applies the legs an Outcome raises.
//
// # Input and output
//
// A screen's Input is the shim's already-redacted window plan (one to
// MaxWindows windows of at most WindowChars UTF-16 code units, and whether
// the content ran past the last window), the shim's local heuristic scores
// and the untrusted source the content came from. Its Outcome is a
// decision (pass, escalate or deny), the composed scores, a closed Reason,
// a closed gap code and the legs the content raises. No content, endpoint
// text or credential reaches an Outcome.
//
// # Composition
//
// Each production question's score is the higher of the shim's local score
// and Jev's highest answer over the windows that answered, so Jev only ever
// raises a score and a failed window is never read as a 0. An injection
// score at or above DenyAt denies (the content is withheld); any production
// score at or above TaintAt escalates (the untrusted leg rises with the
// content's source). A credentials score at or above TaintAt also raises
// the sensitive leg, whatever question drove the decision.
//
// With Jev configured, content that ran past the last window has a
// scan_limit gap, and content longer than one window with a window that got
// no answer has an unclassified gap. A gap escalates content that would
// otherwise pass; denied content reports no gap. Content that fits one
// window degrades to the local scores on a failure, as it does with Jev not
// configured, and has no gap.
//
// # Endpoint, timeout and breaker
//
// The endpoint and its credential are the monitor's own configuration
// (Config), never a plugin's user configuration. The credential is sent as
// a bearer token to the configured endpoint only: redirects are not
// followed, the endpoint must be https (or http to a loopback address), and
// the Credential type formats as [REDACTED].
//
// Every call is bounded by Config.Timeout. A window that failed for a
// transient reason (timeout, network, 429, 5xx) is asked once more; a
// refused or malformed answer is not. A response is validated strictly
// (model spelling, exactly the questions asked, each a number in [0, 1]),
// and anything else is a failure, never a partial answer.
//
// Each endpoint has one production breaker and one shadow breaker, shared
// by every session. A screen that asked the endpoint counts as one event: a
// failure in any window is a failed screen. After DefaultBreakerThreshold
// failed screens in a row the breaker opens for DefaultBreakerCooldown, and
// screens use local scores (State reports degraded). The first screen after
// the cooldown is a trial.
//
// # Cache
//
// Answers are cached per window, keyed by the SHA-256 of the question set,
// the pinned model id and the redacted window, so a wording or model change
// misses by construction. A value is a window's parsed scores, never a
// decision. A failure is never cached. Entries live for DefaultCacheTTL and
// the least recently used is evicted past the size bound. The cache has no
// query endpoint: it is read only by a screen, which applies the answer to
// its own content. A cached answer is used even while the breaker is open.
//
// # Shadow screen
//
// When Config.Shadow is set, every window is also asked the shadow
// questions (the captain wording's four, and the revised wording's
// destructive_command), in parallel with production and without a retry.
// The shadow screen is contrast instrumentation only: its answers go to
// Config.Shadow and never affect an Outcome, and it has its own breaker and
// its own cache namespace.
//
// # Parity
//
// testdata/golden.json is barmkin-mod's TypeScript run over recorded mock
// Jev responses (testdata/golden.gen.ts); golden_test.go replays it against
// this package. The question set's SHA-256 is pinned on both sides. No test
// calls Jev.
package screen
