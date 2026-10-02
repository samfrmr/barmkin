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
}

// HookOutput is the evaluation result returned by the engine.
type HookOutput struct {
	Decision   string `json:"decision"`         // "allow" or "deny"
	Reason     string `json:"reason,omitempty"` // human-readable, shown to LLM on deny
	Rule       string `json:"rule,omitempty"`   // rule name that matched
	ClaudeCode bool   `json:"-"`                // request arrived in Claude Code's PreToolUse wire format; only it can render escalate as ask
}

// toolActions maps Claude Code tool names to semantic action names
// used in the audit log (consistent with sondera's AdapterRequest format).
var toolActions = map[string]string{
	"bash": "ShellCommand", "write": "FileWrite", "edit": "FileEdit",
	"multiedit": "FileEdit", "notebookedit": "FileEdit",
	"read": "FileRead", "glob": "FileSearch", "grep": "ContentSearch",
	"websearch": "WebSearch",
}

// normalize maps Claude Code fields into AdapterRequest fields so the
// audit log has consistent tool/action/trajectory_id regardless of source.
func (r *Request) normalize() {
	if r.Tool == "" && r.ToolName != "" {
		r.Tool = strings.ToLower(r.ToolName)
	}
	if r.Action == "" && r.Tool != "" {
		r.Action = toolActions[r.Tool]
	}
	if r.TrajectoryID == "" && r.SessionID != "" {
		r.TrajectoryID = r.SessionID
	}
	if r.AgentID == "" {
		// Infer agent from wire format: Claude Code uses tool_name/session_id;
		// opencode uses trajectory_id/args. Default to opencode when neither
		// Claude Code field is present.
		if r.isClaudeCode() {
			r.AgentID = "claude-code"
		} else {
			r.AgentID = "opencode"
		}
	}
}

// isClaudeCode reports whether the request arrived in Claude Code's
// PreToolUse wire format (tool_name/session_id), independent of any
// agent_id it carries (Claude Code sets agent_id for subagent calls).
func (r *Request) isClaudeCode() bool {
	return r.ToolName != "" || r.SessionID != ""
}

// extractContent pulls the scannable text from the request.
// Tries AdapterRequest args first (normalized), then falls back to
// Claude Code's raw tool_input format. A read-only search tool's
// query or pattern is data being searched for, never a scan target,
// so for those tools only a path-like field is returned.
func (r *Request) extractContent() string {
	// AdapterRequest: check args for known field names
	if s := firstNonEmpty(r.Args, "command", "path", "url", "content", "patch_text"); s != "" {
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
	if r.readOnly() {
		return ""
	}
	if s := firstNonEmpty(r.Args, "query", "pattern"); s != "" {
		return s
	}
	// Fallback: serialize remaining args
	if len(r.Args) > 0 {
		b, _ := json.Marshal(r.Args)
		return string(b)
	}
	return strings.TrimSpace(string(r.ToolInput))
}

// readOnly reports whether the request's action only reads or
// searches (FileRead, FileSearch, ContentSearch, WebSearch, and any
// future *Search action), so its remaining input is never scanned.
func (r *Request) readOnly() bool {
	return r.Action == "FileRead" || strings.HasSuffix(r.Action, "Search")
}

// fileMutatingTools are the (lowercased) Claude Code tools whose
// individual fields are scanned. Read-only tools (Grep, Glob, Read,
// ...) are scanned on extractContent alone, so a search pattern is
// never treated as a payload.
var fileMutatingTools = map[string]bool{
	"write": true, "edit": true, "multiedit": true, "notebookedit": true,
	"create": true,
}

// filePathFields and filePayloadFields are the tool_input keys whose
// values are each scanned on their own, so a file-mutating tool is
// checked on both its target path and its payload.
var (
	filePathFields    = []string{"path", "filePath", "file_path", "notebook_path"}
	filePayloadFields = []string{
		"content", "old_string", "new_string", "new_source", "file_text",
		"old_str", "new_str",
	}
)

// scanTargets returns the strings the regex rules are matched
// against. For file-mutating tools, paths holds the primary
// extractContent value plus each filePathFields value; every rule
// applies to these. payloads holds each filePayloadFields value from
// Claude Code's tool_input and MultiEdit's edits; path-only rules
// (target: path) never apply to these. Every other tool's
// extractContent value is a payload, so path-only rules never apply
// to a read, search or shell command.
func (r *Request) scanTargets() (paths, payloads []string) {
	if !fileMutatingTools[r.Tool] {
		return nil, []string{r.extractContent()}
	}
	paths = []string{r.extractContent()}
	m := decodeObject(r.ToolInput)
	objs := []map[string]any{m}
	if edits, ok := m["edits"].([]any); ok {
		for _, e := range edits {
			if em, ok := e.(map[string]any); ok {
				objs = append(objs, em)
			}
		}
	}
	for _, o := range objs {
		paths = appendStrings(paths, o, filePathFields)
		payloads = appendStrings(payloads, o, filePayloadFields)
	}
	return paths, payloads
}

// appendStrings appends the non-empty string value of each key in m.
func appendStrings(out []string, m map[string]any, keys []string) []string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// payloadRules returns the rules that apply to payload targets: every
// rule except the path-only (target: path) ones.
func payloadRules(rules []Rule) []Rule {
	var out []Rule
	for _, r := range rules {
		if r.Target != "path" {
			out = append(out, r)
		}
	}
	return out
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
// first non-empty string value for any of the given keys.
func firstString(raw json.RawMessage, keys ...string) string {
	return firstNonEmpty(decodeObject(raw), keys...)
}

// decodeObject unmarshals a JSON object into a map. Anything else
// yields nil.
func decodeObject(raw json.RawMessage) map[string]any {
	if len(raw) == 0 {
		return nil
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
