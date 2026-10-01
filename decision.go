// Decision type and harness output adapters for the dynamic layer.
//
// The regex layer only ever produces Pass or Deny. The dynamic layer
// (dynamic.go, jev.go) adds Escalate: "a human must confirm this call".
// Composition code - never Jev itself - picks the Decision, so the
// dynamic layer can only tighten a verdict, never loosen it: it can
// turn Pass into Escalate or Deny, but never produce Pass once the
// regex layer (or an unavailable/degraded dynamic layer under a strict
// on_unavailable posture) has already said otherwise.
package main

import "encoding/json"

// Decision is the three-way outcome the dynamic layer can produce.
type Decision int

const (
	Pass Decision = iota
	Escalate
	Deny
)

// String renders the Decision as the audit-log/HookOutput "decision"
// value. Pass is "allow" for backward compatibility with the regex
// layer's existing log field.
func (d Decision) String() string {
	switch d {
	case Deny:
		return "deny"
	case Escalate:
		return "escalate"
	default:
		return "allow"
	}
}

// claudeCodeEscalateOutput is the Claude Code PreToolUse hook JSON that
// forces a permission prompt even in auto mode. Emitted on stdout with
// exit 0; "Deny" still uses the pre-existing exit-2-plus-stderr path.
type claudeCodeEscalateOutput struct {
	HookSpecificOutput claudeCodeHookSpecific `json:"hookSpecificOutput"`
}

type claudeCodeHookSpecific struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// renderEscalateJSON builds the Claude Code PreToolUse "ask" payload.
func renderEscalateJSON(reason string) string {
	out := claudeCodeEscalateOutput{
		HookSpecificOutput: claudeCodeHookSpecific{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "ask",
			PermissionDecisionReason: reason,
		},
	}
	b, _ := json.Marshal(out)
	return string(b)
}

// copilotCLIOutput is GitHub Copilot CLI's preToolUse hook JSON output:
// {"permissionDecision":"allow"|"deny"|"ask","permissionDecisionReason":"…"}
// (report.md §5c/§4.5). Unlike Claude Code, no documented case treats a
// silent exit 0 as "no decision" on this harness - every documented
// example emits explicit JSON - so Barmkin renders this on every
// outcome for Copilot CLI, including pass, rather than relying on
// silence.
type copilotCLIOutput struct {
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// renderCopilotCLIOutput builds the Copilot CLI preToolUse payload.
// decision is "allow", "ask", or "deny".
func renderCopilotCLIOutput(decision, reason string) string {
	out := copilotCLIOutput{PermissionDecision: decision, PermissionDecisionReason: reason}
	b, _ := json.Marshal(out)
	return string(b)
}
