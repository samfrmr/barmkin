// Request/response types and matching logic.
//
// Barmkin accepts two input formats:
//
//  1. AdapterRequest - sent by the opencode TS plugin (barmkin.ts).
//     Normalized with trajectory_id, agent_id, tool, action, args.
//
//  2. Claude Code - sent by Claude Code's PreToolUse hook.
//     Uses tool_name, tool_input, and session_id.
//
// normalize() maps Claude Code fields into AdapterRequest fields so
// the audit log is consistent regardless of input source.

package main

import (
	"encoding/json"
	"strings"
)

// Request is the unified input structure. Fields from both formats
// are populated by JSON unmarshaling; normalize() reconciles them.
type Request struct {
	// AdapterRequest fields (from opencode TS plugin)
	TrajectoryID string         `json:"trajectory_id"`
	AgentID      string         `json:"agent_id"`
	Tool         string         `json:"tool"`
	Action       string         `json:"action"`
	Args         map[string]any `json:"args"`
	Cwd          string         `json:"cwd,omitempty"`
	EventType    string         `json:"event_type,omitempty"`

	// Claude Code fields (from PreToolUse hook)
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	Command        string          `json:"command"`
	SessionID      string          `json:"session_id"`
	PermissionMode string          `json:"permission_mode,omitempty"` // e.g. "auto", "bypassPermissions", "dontAsk"

	// GitHub Copilot CLI preToolUse fields (camelCase; report.md §5c,
	// §4.5: "the preToolUse dialect documented... for the CLI (camelCase
	// toolName/toolArgs, bare permissionDecision)"). Distinct from Claude
	// Code's snake_case tool_name/tool_input, so presence of either
	// toolName or toolArgs with no Claude Code field identifies this
	// harness in normalize().
	ToolNameCamel  string          `json:"toolName,omitempty"`
	ToolArgsCamel  json.RawMessage `json:"toolArgs,omitempty"`
	SessionIDCamel string          `json:"sessionId,omitempty"`
}

// HookOutput is the evaluation result returned by the engine.
type HookOutput struct {
	Decision string `json:"decision"`         // "allow" or "deny"
	Reason   string `json:"reason,omitempty"` // human-readable, shown to LLM on deny
	Rule     string `json:"rule,omitempty"`   // rule name that matched

	// AgentID is never serialized (json:"-"): it only tells cmdEval
	// which harness-specific output dialect to render (Claude Code's
	// silent-exit-0/ask-JSON vs. Copilot CLI's always-explicit
	// permissionDecision JSON, report.md §5c). Excluding it from the
	// wire format keeps HookOutput's JSON byte-identical to before this
	// field existed, which the golden-equivalence tests rely on.
	AgentID string `json:"-"`
}

// toolActions maps Claude Code tool names to semantic action names
// used in the audit log (consistent with sondera's AdapterRequest format).
var toolActions = map[string]string{
	"bash": "ShellCommand", "write": "FileWrite", "edit": "FileEdit",
	"multiedit": "FileEdit", "notebookedit": "FileEdit",
	"read": "FileRead", "glob": "FileSearch", "grep": "ContentSearch",
}

// normalize maps Claude Code and Copilot CLI fields into AdapterRequest
// fields so the audit log has consistent tool/action/trajectory_id
// regardless of source.
func (r *Request) normalize() {
	if r.Tool == "" && r.ToolName != "" {
		r.Tool = strings.ToLower(r.ToolName)
	}
	if r.Tool == "" && r.ToolNameCamel != "" {
		r.Tool = strings.ToLower(r.ToolNameCamel)
	}
	if r.Action == "" && r.Tool != "" {
		r.Action = toolActions[r.Tool]
	}
	if r.TrajectoryID == "" && r.SessionID != "" {
		r.TrajectoryID = r.SessionID
	}
	if r.TrajectoryID == "" && r.SessionIDCamel != "" {
		r.TrajectoryID = r.SessionIDCamel
	}
	if r.AgentID == "" {
		// Infer agent from wire format: Claude Code uses snake_case
		// tool_name/session_id; Copilot CLI's preToolUse hook uses
		// camelCase toolName/toolArgs (report.md §5c); opencode uses
		// trajectory_id/args. Default to opencode when none of the
		// harness-specific fields are present.
		switch {
		case r.ToolName != "" || r.SessionID != "":
			r.AgentID = "claude-code"
		case r.ToolNameCamel != "" || len(r.ToolArgsCamel) > 0:
			r.AgentID = "copilot-cli"
		default:
			r.AgentID = "opencode"
		}
	}
}

// extractContent pulls the scannable text from the request.
// Tries AdapterRequest args first (normalized), then falls back to
// Claude Code's raw tool_input format.
func (r *Request) extractContent() string {
	// AdapterRequest: check args for known field names
	if s := firstNonEmpty(r.Args, "command", "path", "url", "content", "query", "pattern", "patch_text"); s != "" {
		return s
	}
	// Claude Code: top-level command field
	if r.Command != "" {
		return r.Command
	}
	// Claude Code: tool_input JSON object. file_path is Write/Edit's
	// actual field name (report.md §2.7); without it, a file-tool
	// target path was never scanned by any rule.
	if s := firstString(r.ToolInput, "command", "path", "filePath", "file_path", "url", "content"); s != "" {
		return s
	}
	// Copilot CLI: toolArgs JSON object (camelCase dialect, §5c).
	if s := firstString(r.ToolArgsCamel, "command", "path", "filePath", "file_path", "url", "content"); s != "" {
		return s
	}
	// Fallback: serialize remaining args
	if len(r.Args) > 0 {
		b, _ := json.Marshal(r.Args)
		return string(b)
	}
	if readOnlyActions[r.Action] {
		return ""
	}
	return strings.TrimSpace(string(r.ToolInput))
}

// readOnlyActions are the toolActions whose remaining tool_input
// (e.g. a Grep/Glob search pattern) is data being searched for, never
// a scan target.
var readOnlyActions = map[string]bool{
	"FileRead": true, "FileSearch": true, "ContentSearch": true,
}

// fileMutatingTools are the (lowercased) Claude Code and Copilot CLI
// tools whose individual fields are scanned. Read-only tools (Grep,
// Glob, Read, ...) are scanned on extractContent alone, so a search
// pattern is never treated as a payload.
var fileMutatingTools = map[string]bool{
	"write": true, "edit": true, "multiedit": true, "notebookedit": true,
	"create": true,
}

// fileToolFields are the tool_input/toolArgs keys whose values are
// each scanned on their own, so a file-mutating tool is checked on
// both its target path and its payload.
var fileToolFields = []string{
	"path", "filePath", "file_path", "notebook_path", "content",
	"old_string", "new_string", "new_source", "file_text", "old_str",
	"new_str",
}

// scanTargets returns every string the regex rules are matched
// against: the primary extractContent value plus, for file-mutating
// tools, each present fileToolFields value from Claude Code's
// tool_input, Copilot CLI's toolArgs, and MultiEdit's edits. Path
// rules anchored with ^...$ still see the bare path, while content
// rules also see the written payload.
func (r *Request) scanTargets() []string {
	targets := []string{r.extractContent()}
	if !fileMutatingTools[r.Tool] {
		return targets
	}
	for _, raw := range []json.RawMessage{r.ToolInput, r.ToolArgsCamel} {
		m := decodeObject(raw)
		objs := []map[string]any{m}
		if edits, ok := m["edits"].([]any); ok {
			for _, e := range edits {
				if em, ok := e.(map[string]any); ok {
					objs = append(objs, em)
				}
			}
		}
		for _, o := range objs {
			for _, k := range fileToolFields {
				if s, ok := o[k].(string); ok && s != "" {
					targets = append(targets, s)
				}
			}
		}
	}
	return targets
}

// firstNonEmpty returns the first non-empty string value for any of
// the given keys in the map.
func firstNonEmpty(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// firstString unmarshals a JSON RawMessage into a map and returns the
// first non-empty string value for any of the given keys. A JSON
// string holding an encoded object (Copilot CLI's toolArgs) is
// decoded first.
func firstString(raw json.RawMessage, keys ...string) string {
	return firstNonEmpty(decodeObject(raw), keys...)
}

// decodeObject unmarshals a JSON object, or a JSON string holding an
// encoded object, into a map. Anything else yields nil.
func decodeObject(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var encoded string
	if json.Unmarshal(raw, &encoded) == nil {
		raw = json.RawMessage(encoded)
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// match checks rules in order. An allow rule that matches overrides
// all deny rules and returns nil (allow). Otherwise the first deny
// match wins and that rule is returned.
//
// This allows narrow allow rules to exempt specific patterns from
// broad deny rules, e.g.:
//
//   - name: "allow-tmp-rm"
//     pattern: 'rm\s+-rf\s+/tmp/'
//     action: "allow"
//
//   - name: "rm-rf-force"
//     pattern: 'rm\s+-rf\b'
//     action: "deny"
func match(content string, rules []Rule) *Rule {
	var firstDeny *Rule
	for i := range rules {
		if rules[i].regex == nil || !rules[i].regex.MatchString(content) {
			continue
		}
		if rules[i].Action == "allow" {
			return nil
		}
		if firstDeny == nil {
			firstDeny = &rules[i]
		}
	}
	return firstDeny
}

// matchedAllowRule reports whether an explicit regex allow rule fired
// for content, independent of match()'s nil-on-allow-or-no-match
// result. Used only by the dynamic layer's skip_allow_rules gate (D6),
// so it costs nothing on the zero-config path where dynamic is
// disabled and this is never called.
func matchedAllowRule(content string, rules []Rule) bool {
	for i := range rules {
		if rules[i].Action == "allow" && rules[i].regex != nil && rules[i].regex.MatchString(content) {
			return true
		}
	}
	return false
}

// truncate shortens a string to n characters, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}
