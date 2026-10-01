// Dynamic layer: gate, state builder, composition, and the per-session
// circuit breaker. This runs only after the regex layer found nothing
// to deny (engine.go), and only for calls the gate selects.
//
// The invariant this file must preserve: the dynamic layer never
// produces Pass from Jev's answers alone being favorable beyond what
// composeOutcome allows, and it never overrides a regex deny (callers
// never reach this file on a regex deny - see engine.go). Jev is
// never the component that permits.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// dynamicQuestion is one POC question: a Noul with a two-sided
// severity. Hazard questions reject straight to Deny; soft questions
// reject to Escalate (nothing in the POC can turn a soft rejection
// back into Pass - there is no intent signal to clear it, see
// report.md §5a). Adapted from pi-jev-auto-mode's calibration; the POC
// ships only the two questions named in the demo brief.
type dynamicQuestion struct {
	ID           string
	Severity     string // "hazard" | "soft"
	RejectAt     float64
	Outcome      Decision
	Instructions string
}

var defaultQuestions = []dynamicQuestion{
	{ID: "no_secret_egress", Severity: "hazard", RejectAt: 0.03, Outcome: Deny, Instructions: "Does the command send credentials, keys, or tokens to a network endpoint?"},
	{ID: "no_outward_effect", Severity: "soft", RejectAt: 0.10, Outcome: Escalate, Instructions: "Does the command have any effect outside this machine, such as publishing, deploying, purchasing, or changing third-party state?"},
}

// dynamicResult carries everything engine.go needs to render a
// HookOutput and an audit-log "dynamic" block for one evaluation.
type dynamicResult struct {
	Mode             string
	Outcome          Decision // what actually happened this call
	WouldDecision    Decision // what enforce mode would have done (== Outcome in enforce mode)
	FailMode         string   // set when Outcome came from on_unavailable or the breaker
	ErrorKind        string
	Provider         string
	Model            string
	RequestID        string
	LatencyMs        float64
	InputTokens      int
	CostUSD          float64
	DecidingQuestion string
	Probabilities    map[string]float64
	Thresholds       map[string]float64
	Breaker          string // closed | open | half_open
}

// shouldGate decides whether this call reaches the dynamic layer at
// all. matchedAllow is whether an explicit regex allow rule fired
// (not merely "no deny matched") - D6 default skips the dynamic layer
// for those, since they are the deployed org's explicit exemptions.
func (d Dynamic) shouldGate(req Request, content string, matchedAllow bool) bool {
	if !d.Enabled {
		return false
	}
	if matchedAllow && d.Gate.SkipAllowRules {
		return false
	}
	if !containsFold(d.Gate.Tools, req.Tool) {
		return false
	}
	if len(d.Gate.PermissionModes) > 0 && req.PermissionMode != "" && !containsFold(d.Gate.PermissionModes, req.PermissionMode) {
		return false
	}
	if d.Gate.SkipReadOnly && isReadOnlyCommand(content) {
		return false
	}
	return true
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// readOnlyCommands is the built-in fast-path allowlist: a command
// whose every "&& ; |" segment starts with one of these is skipped,
// even inside a gated session, per D10. Destructive variants (e.g.
// "ls && rm -rf x") are still judged, because the *second* segment's
// leading word isn't in this list.
var readOnlyCommands = map[string]bool{
	"ls": true, "cat": true, "head": true, "tail": true, "grep": true,
	"find": true, "pwd": true, "echo": true, "wc": true, "which": true,
	"type": true, "env": true, "date": true, "whoami": true, "id": true,
	"diff": true, "file": true, "stat": true, "less": true, "more": true,
	"git": true, // narrowed below: only read-only git subcommands
}

var readOnlyGitSubcommands = map[string]bool{
	"status": true, "log": true, "diff": true, "show": true, "branch": true,
	"remote": true, "blame": true, "rev-parse": true,
}

var segmentSplit = regexp.MustCompile(`&&|\|\||[;|]`)

// isReadOnlyCommand reports whether every "&&"/";"/"|" segment of cmd
// begins with a known read-only command (and, for git, a read-only
// subcommand). An empty or unparsable command is not read-only.
func isReadOnlyCommand(cmd string) bool {
	segments := segmentSplit.Split(cmd, -1)
	found := false
	for _, seg := range segments {
		fields := strings.Fields(strings.TrimSpace(seg))
		if len(fields) == 0 {
			continue
		}
		found = true
		head := fields[0]
		if !readOnlyCommands[head] {
			return false
		}
		if head == "git" {
			if len(fields) < 2 || !readOnlyGitSubcommands[fields[1]] {
				return false
			}
		}
	}
	return found
}

// runDynamic executes one dynamic-layer evaluation: breaker check,
// Jev request (unless the breaker is open), composition, and the
// shadow/enforce gate on the final acted decision.
func runDynamic(cfg Dynamic, req Request, content string) *dynamicResult {
	res := &dynamicResult{Mode: cfg.Mode, Thresholds: thresholdMap(cfg), Provider: providerName(cfg.Provider.BaseURL)}

	sessionID := req.TrajectoryID
	st := loadBreakerState(sessionID)
	open, halfOpen := breakerIsOpen(cfg.Breaker, st)

	var (
		probs   map[string]float64
		modelID string
		reqID   string
		jerr    error
		latency time.Duration
	)

	switch {
	case open:
		res.Breaker = "open"
		jerr = &jevError{kind: "breaker_open"}
	default:
		if halfOpen {
			res.Breaker = "half_open"
		} else {
			res.Breaker = "closed"
		}
		client, cerr := newJevClient(cfg.Provider)
		if cerr != nil {
			jerr = cerr
		} else {
			state := map[string]string{
				"command": redact(truncate(content, 4000)),
				"cwd":     req.Cwd,
			}
			questions := make(map[string]jevQuestion, len(defaultQuestions))
			for _, q := range defaultQuestions {
				questions[q.ID] = jevQuestion{Type: "noul", Instructions: q.Instructions}
			}
			ctx, cancel := context.WithTimeout(context.Background(), client.timeout)
			start := time.Now()
			probs, modelID, reqID, jerr = client.ask(ctx, state, questions)
			latency = time.Since(start)
			cancel()
		}
	}

	res.Model = modelID
	res.RequestID = reqID
	res.LatencyMs = float64(latency.Microseconds()) / 1000.0

	if jerr != nil {
		res.ErrorKind = errKind(jerr)
		res.FailMode = "on_unavailable"
		outcome := onUnavailableOutcome(cfg, req.PermissionMode)
		res.Outcome = outcome
		res.WouldDecision = outcome
		updateBreakerOnFailure(cfg.Breaker, sessionID, st)
		return res
	}

	resetBreaker(cfg.Breaker, sessionID, st)
	res.Probabilities = probs
	outcome, deciding := composeOutcome(cfg, probs)
	res.WouldDecision = outcome
	res.DecidingQuestion = deciding
	if cfg.Mode == "enforce" {
		res.Outcome = outcome
	} else {
		res.Outcome = Pass
	}
	return res
}

// thresholdMap merges the default per-question reject-at thresholds
// with any config override, for logging and composition.
func thresholdMap(cfg Dynamic) map[string]float64 {
	out := make(map[string]float64, len(defaultQuestions))
	for _, q := range defaultQuestions {
		out[q.ID] = q.RejectAt
	}
	for id, t := range cfg.Thresholds {
		out[id] = t
	}
	return out
}

// composeOutcome turns Jev's probabilities into a Decision in code,
// never in the model: a clear hazard rejection (p <= threshold) wins
// immediately and denies; otherwise a clear soft rejection escalates;
// the middle band and every "safe" answer pass. Hazard beats soft when
// both reject in a single call.
func composeOutcome(cfg Dynamic, probs map[string]float64) (Decision, string) {
	thresholds := thresholdMap(cfg)
	deciding := ""
	best := Pass
	for _, q := range defaultQuestions {
		p, ok := probs[q.ID]
		if !ok {
			continue
		}
		if p > thresholds[q.ID] {
			continue
		}
		if q.Outcome == Deny {
			return Deny, q.ID
		}
		if best == Pass {
			best = Escalate
			deciding = q.ID
		}
	}
	return best, deciding
}

// onUnavailableOutcome resolves the configured fail mode, with an
// optional per-permission_mode override (e.g. deny under
// bypassPermissions until a human verifies hook "ask" is honoured
// there - see report.md §5c). Unknown/unsupported values (e.g. "halt",
// out of scope for this Claude-Code-only demo) fail to the strictest
// supported option, Escalate, rather than silently passing.
func onUnavailableOutcome(cfg Dynamic, permissionMode string) Decision {
	val := cfg.OnUnavailable
	if permissionMode != "" {
		if v, ok := cfg.OnUnavailableByMode[permissionMode]; ok {
			val = v
		}
	}
	switch val {
	case "pass", "":
		return Pass
	case "deny":
		return Deny
	case "escalate":
		return Escalate
	default:
		return Escalate
	}
}

// --- per-session breaker state ---------------------------------------------

// breakerState is persisted at ~/.barmkin/state/<session>.json (0600).
// It may only make Barmkin stricter: a deleted or forged file just
// triggers a fresh probe, never an implicit allow.
type breakerState struct {
	Failures int       `json:"failures"`
	OpenedAt time.Time `json:"opened_at,omitempty"`
}

var sessionIDSanitizer = regexp.MustCompile(`[^A-Za-z0-9_-]`)

func breakerPath(sessionID string) string {
	safe := sessionIDSanitizer.ReplaceAllString(sessionID, "_")
	if safe == "" {
		safe = "unknown"
	}
	return filepath.Join(homeDir(), ".barmkin", "state", safe+".json")
}

func loadBreakerState(sessionID string) breakerState {
	data, err := os.ReadFile(breakerPath(sessionID))
	if err != nil {
		return breakerState{}
	}
	var st breakerState
	if json.Unmarshal(data, &st) != nil {
		return breakerState{}
	}
	return st
}

// saveBreakerStateAtomic writes via write-temp-then-rename so a
// concurrent reader (parallel tool calls each spawn their own
// process) never observes a partial write.
func saveBreakerStateAtomic(sessionID string, st breakerState) {
	path := breakerPath(sessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	tmp := fmt.Sprintf("%s.tmp-%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	os.Rename(tmp, path)
}

// breakerIsOpen reports whether the breaker currently short-circuits
// network calls (open), or whether a cooldown has elapsed and this
// call should probe again while treating any further failure as
// re-opening the breaker (halfOpen).
func breakerIsOpen(cfg DynamicBreaker, st breakerState) (open, halfOpen bool) {
	if !cfg.Enabled || st.OpenedAt.IsZero() {
		return false, false
	}
	cooldown := time.Duration(cfg.CooldownS) * time.Second
	if cooldown <= 0 {
		cooldown = 60 * time.Second
	}
	if time.Since(st.OpenedAt) >= cooldown {
		return false, true
	}
	return true, false
}

func updateBreakerOnFailure(cfg DynamicBreaker, sessionID string, st breakerState) {
	if !cfg.Enabled {
		return
	}
	st.Failures++
	threshold := cfg.OpenAfterFailures
	if threshold <= 0 {
		threshold = 1
	}
	if st.Failures >= threshold {
		st.OpenedAt = time.Now().UTC()
	}
	saveBreakerStateAtomic(sessionID, st)
}

func resetBreaker(cfg DynamicBreaker, sessionID string, st breakerState) {
	if !cfg.Enabled || (st.Failures == 0 && st.OpenedAt.IsZero()) {
		return
	}
	saveBreakerStateAtomic(sessionID, breakerState{})
}

// toHookOutput renders the dynamic result as the HookOutput engine.go
// returns, with a reason string that names the deciding question and
// probability (or the failure kind) for transparency to the human who
// may see it on an escalate prompt.
func (d *dynamicResult) toHookOutput() HookOutput {
	switch {
	case d.ErrorKind != "":
		return HookOutput{
			Decision: d.Outcome.String(),
			Reason:   fmt.Sprintf("Barmkin semantic check unavailable (%s); %s", d.ErrorKind, fallbackVerb(d.Outcome)),
		}
	case d.DecidingQuestion != "":
		return HookOutput{
			Decision: d.Outcome.String(),
			Reason:   fmt.Sprintf("semantic check: %s (p=%.2f)", d.DecidingQuestion, d.Probabilities[d.DecidingQuestion]),
		}
	default:
		return HookOutput{Decision: d.Outcome.String()}
	}
}

func fallbackVerb(d Decision) string {
	switch d {
	case Deny:
		return "blocking until it recovers"
	case Escalate:
		return "needs your approval"
	default:
		return "continuing (shadow/fail-open)"
	}
}

// toAudit renders the dynamic result as the audit-log "dynamic" block
// (report.md §5f). Probabilities are logged even on pass, so shadow
// mode is calibratable.
func (d *dynamicResult) toAudit() *DynamicAudit {
	return &DynamicAudit{
		Mode:             d.Mode,
		Outcome:          d.Outcome.String(),
		WouldDecision:    d.WouldDecision.String(),
		FailMode:         d.FailMode,
		Error:            d.ErrorKind,
		Provider:         d.Provider,
		Model:            d.Model,
		RequestID:        d.RequestID,
		LatencyMs:        d.LatencyMs,
		InputTokens:      d.InputTokens,
		CostUSD:          d.CostUSD,
		DecidingQuestion: d.DecidingQuestion,
		Probabilities:    d.Probabilities,
		Thresholds:       d.Thresholds,
		Breaker:          d.Breaker,
	}
}
