// Audit log - appends each evaluation decision as a JSON line.
//
// Format is aligned with sondera's AuditEntry so logs from both
// guardrails can be aggregated and queried together.
//
// Each line:
//
//	{"ts":"2026-06-30T01:00:00Z","trajectory_id":"sess-123","tool":"bash",
//	 "action":"ShellCommand","decision":"deny","reason":"Recursive force-delete",
//	 "duration_ms":0.064,"rule":"rm-rf-force","content":"rm -rf /tmp",
//	 "agent":"claude-code"}

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// DecisionLogger appends AuditEntry records as JSON lines to a file.
// Nil when logging is disabled (empty path).
type DecisionLogger struct {
	mu   sync.Mutex
	file *os.File
}

// AuditEntry is the on-wire audit record. Field names match sondera's
// format, with barmkin-specific additions (rule, content, agent).
type AuditEntry struct {
	TS           string  `json:"ts"`                // RFC3339 UTC timestamp (set by Write)
	TrajectoryID string  `json:"trajectory_id"`     // session ID
	Tool         string  `json:"tool"`              // e.g. "bash", "read", "edit"
	Action       string  `json:"action"`            // e.g. "ShellCommand", "FileRead"
	Decision     string  `json:"decision"`          // "allow" or "deny"
	Reason       string  `json:"reason,omitempty"`  // rule reason, shown to LLM
	DurationMs   float64 `json:"duration_ms"`       // evaluation time
	Rule         string  `json:"rule,omitempty"`    // barmkin: matched rule name
	Content      string  `json:"content,omitempty"` // barmkin: truncated command content
	Agent        string  `json:"agent,omitempty"`   // barmkin: agent identifier

	// Dynamic-layer additions (all omitempty, so lines without the
	// dynamic layer are byte-identical to before it existed).
	Layer          string        `json:"layer,omitempty"`           // "regex" | "dynamic" (absent == regex, for old lines)
	PermissionMode string        `json:"permission_mode,omitempty"` // from the Claude Code hook input when present
	Dynamic        *DynamicAudit `json:"dynamic,omitempty"`
}

// DynamicAudit is the per-evaluation detail logged when the dynamic
// (Jev) layer ran. See report.md §5f for the field meanings; "decision"
// (AuditEntry.Decision) already carries the acted-on outcome including
// its new "escalate" value, so this block is the *why*.
type DynamicAudit struct {
	Mode             string             `json:"mode"`                     // shadow | enforce
	Outcome          string             `json:"outcome"`                  // pass | escalate | deny (what actually happened)
	WouldDecision    string             `json:"would_decision,omitempty"` // what enforce mode would have done
	FailMode         string             `json:"fail_mode,omitempty"`      // set when Outcome came from on_unavailable/breaker
	Error            string             `json:"error,omitempty"`          // timeout | network | http_<code> | malformed_response | no_key | breaker_open | ...
	Provider         string             `json:"provider,omitempty"`
	Model            string             `json:"model,omitempty"`
	RequestID        string             `json:"request_id,omitempty"`
	LatencyMs        float64            `json:"latency_ms,omitempty"`
	InputTokens      int                `json:"input_tokens,omitempty"`
	CostUSD          float64            `json:"cost_usd,omitempty"`
	DecidingQuestion string             `json:"deciding_question,omitempty"`
	Probabilities    map[string]float64 `json:"probabilities,omitempty"`
	Thresholds       map[string]float64 `json:"thresholds,omitempty"`
	Breaker          string             `json:"breaker,omitempty"` // closed | open | half_open
}

// newDecisionLogger opens (or creates) the log file for appending.
// Returns nil if path is empty - callers must check for nil or use
// the nil-safe Write method.
func newDecisionLogger(path string) *DecisionLogger {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[barmkin] log %s: %v (disabled)\n", path, err)
		return nil
	}
	return &DecisionLogger{file: f}
}

// Write appends one AuditEntry as a JSON line. No-op if logger is nil.
// Sets the timestamp automatically.
func (l *DecisionLogger) Write(entry AuditEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	entry.TS = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.file.Write(line)
	l.file.Write([]byte("\n"))
}

// Close closes the underlying file. No-op if logger is nil.
func (l *DecisionLogger) Close() {
	if l != nil && l.file != nil {
		l.file.Close()
	}
}
