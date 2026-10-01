package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Config-driven rule tests ────────────────────────────────────────────
// Loads rules.yaml and verifies each rule's example matches.
// Adding a rule with an example automatically adds a test.

func TestRulesFromConfig(t *testing.T) {
	cfg, err := loadConfig(rulesYAMLPath(t))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("no rules in config")
	}

	for _, r := range cfg.Rules {
		t.Run(r.Name, func(t *testing.T) {
			if r.Example == "" {
				t.Skip("no example")
			}
			m := match(r.Example, cfg.Rules)
			if m == nil {
				t.Errorf("example %q did not match any rule", r.Example)
				return
			}
			if m.Name != r.Name {
				t.Errorf("example %q matched %q, want %q", r.Example, m.Name, r.Name)
			}
		})
	}
}

// falsePositiveCorpus is shared with TestGoldenEquivalence_NoDynamicBlock
// (dynamic_test.go), which replays it through the full engine to prove
// the dynamic layer's presence (absent/disabled) never changes regex
// behavior for any of these.
var falsePositiveCorpus = []string{
	// common dev commands
	"ls -la", "cat README.md", "git status", "npm install",
	"git push origin main", "rm file.txt", "git log --oneline",
	"echo hello", "cargo build --release", "grep TODO src/",
	"go test ./...", "python script.py", "make build",
	"docker ps", "docker logs web", "kubectl get pods",
	"ssh user@host", "scp file.txt user@host:~/",
	"curl https://api.github.com/repos", "wget https://releases.com/pkg.tar.gz",
	"pip install requests", "npm install express",
	"chmod +x deploy.sh", "chown dave README.md",
	"export PATH=/usr/local/bin:$PATH", "source venv/bin/activate",
	// safe database
	"SELECT * FROM users", "INSERT INTO users VALUES (1)",
	"UPDATE users SET name='x' WHERE id=1",
	// safe with keywords that look dangerous
	"echo 'do not DROP anything'",
	"cat docs/shutdown-procedure.md",
	"grep -r 'fork' src/",
	"git log --grep='force'",
	"docker rm old-container",
	"kubectl get namespace",
	"history | tail -5",
	"cat ~/.bashrc",
	// sensitive-looking but benign file_path targets (not the exact
	// file the new path rules above target)
	"/home/user/.ssh/config",
	"/home/user/.ssh/known_hosts",
	"/home/user/project/.env.example",
	"/home/user/project/.envrc",
	"/home/user/.aws/config",
}

func TestFalsePositives(t *testing.T) {
	cfg, err := loadConfig(rulesYAMLPath(t))
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	for _, cmd := range falsePositiveCorpus {
		if m := match(cmd, cfg.Rules); m != nil {
			t.Errorf("safe %q matched %q", cmd, m.Name)
		}
	}
}

func rulesYAMLPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"rules.yaml",
		filepath.Join(os.Getenv("HOME"), ".barmkin", "rules.yaml"),
	} {
		if fileExists(p) {
			return p
		}
	}
	t.Fatal("rules.yaml not found")
	return ""
}

// ── ExtractContent ───────────────────────────────────────────────────────

func TestExtractContent(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want string
	}{
		{
			"adapter args command",
			Request{Args: map[string]any{"command": "ls -la"}, Tool: "bash", Action: "ShellCommand"},
			"ls -la",
		},
		{
			"adapter args path",
			Request{Args: map[string]any{"path": "/etc/passwd"}, Tool: "read", Action: "FileRead"},
			"/etc/passwd",
		},
		{
			"adapter args url",
			Request{Args: map[string]any{"url": "http://x.com"}, Tool: "webfetch", Action: "WebFetch"},
			"http://x.com",
		},
		{
			"claude-code tool_input",
			Request{ToolInput: []byte(`{"command":"echo hi"}`), ToolName: "Bash"},
			"echo hi",
		},
		{
			"claude-code top-level command",
			Request{Command: "rm -rf /"},
			"rm -rf /",
		},
		{
			"claude-code Write/Edit file_path",
			Request{ToolInput: []byte(`{"file_path":"/home/u/.ssh/authorized_keys"}`), ToolName: "Edit"},
			"/home/u/.ssh/authorized_keys",
		},
		{
			"copilot-cli toolArgs command",
			Request{ToolNameCamel: "Bash", ToolArgsCamel: []byte(`{"command":"ls -la"}`)},
			"ls -la",
		},
		{
			"copilot-cli string-encoded toolArgs command",
			Request{ToolNameCamel: "bash", ToolArgsCamel: []byte(`"{\"command\":\"rm -rf /\"}"`)},
			"rm -rf /",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.req.extractContent(); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── Engine ───────────────────────────────────────────────────────────────

func mustRules(t *testing.T, rules ...[2]string) []Rule {
	t.Helper()
	var out []Rule
	for _, r := range rules {
		ru := Rule{Name: r[0], Pattern: r[1], Action: "deny", Reason: "test"}
		if err := ru.compile(); err != nil {
			t.Fatalf("rule %q: %v", r[0], err)
		}
		out = append(out, ru)
	}
	return out
}

func TestEngine_EvaluateDeny(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(Request{
		Tool: "bash", Action: "ShellCommand",
		Args: map[string]any{"command": "rm -rf /tmp"},
	})
	if r := e.evaluate(input); r.Decision != "deny" || r.Rule != "rm-rf" {
		t.Errorf("got %+v", r)
	}
}

func TestEngine_EvaluateClaudeCode(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": "rm -rf /home"},
	})
	if e.evaluate(input).Decision != "deny" {
		t.Error("expected deny")
	}
}

func TestEngine_EvaluateAllow(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(Request{
		Tool: "bash", Action: "ShellCommand",
		Args: map[string]any{"command": "ls -la"},
	})
	if e.evaluate(input).Decision != "allow" {
		t.Error("expected allow")
	}
}

func TestEngine_EvaluateCopilotCLI_SetsAgentID(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(map[string]any{
		"toolName": "Bash",
		"toolArgs": map[string]any{"command": "ls -la"},
	})
	r := e.evaluate(input)
	if r.Decision != "allow" {
		t.Fatalf("got %+v", r)
	}
	if r.AgentID != "copilot-cli" {
		t.Errorf("AgentID = %q, want copilot-cli", r.AgentID)
	}
}

func TestEngine_EvaluateCopilotCLI_Deny(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(map[string]any{
		"toolName": "Bash",
		"toolArgs": map[string]any{"command": "rm -rf /tmp"},
	})
	r := e.evaluate(input)
	if r.Decision != "deny" || r.AgentID != "copilot-cli" {
		t.Errorf("got %+v", r)
	}
}

func TestEngine_EvaluateFileTools_ScanPathAndPayload(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t,
		[2]string{"private-key-block", `-----BEGIN\s+(RSA|EC|OPENSSH|PRIVATE)\s+(PRIVATE\s+)?KEY-----`},
		[2]string{"github-token", `\bgh[pousr]_[A-Za-z0-9]{36}\b`},
		[2]string{"ssh-private-key-path", `^[^\s]*\.ssh/(id_rsa|id_dsa|id_ecdsa|id_ed25519)(\.pub)?$`},
	)})
	cases := []struct {
		name  string
		input map[string]any
		want  string
	}{
		{"claude Write content", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/tmp/k.pem", "content": "-----BEGIN RSA PRIVATE KEY-----\nMIIE"}}, "private-key-block"},
		{"claude Edit new_string", map[string]any{"tool_name": "Edit", "tool_input": map[string]any{"file_path": "/tmp/x", "old_string": "a", "new_string": "token=ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII"}}, "github-token"},
		{"claude Write sensitive path", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/home/u/.ssh/id_rsa", "content": "harmless"}}, "ssh-private-key-path"},
		{"copilot edit new_str", map[string]any{"toolName": "edit", "toolArgs": `{"path":"/tmp/x","old_str":"a","new_str":"-----BEGIN OPENSSH PRIVATE KEY-----"}`}, "private-key-block"},
		{"claude MultiEdit new_string", map[string]any{"tool_name": "MultiEdit", "tool_input": map[string]any{"file_path": "/tmp/x", "edits": []any{map[string]any{"old_string": "a", "new_string": "-----BEGIN EC PRIVATE KEY-----"}}}}, "private-key-block"},
		{"claude Write benign", map[string]any{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/tmp/notes.md", "content": "hello"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input, _ := json.Marshal(tc.input)
			r := e.evaluate(input)
			if r.Rule != tc.want {
				t.Errorf("got %+v, want rule %q", r, tc.want)
			}
		})
	}
}

func TestEngine_EvaluateSearchTools_PatternNotScanned(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t,
		[2]string{"rm-rf-force", `rm\s+-rf\b`},
		[2]string{"drop-table", `(?i)DROP\s+TABLE`},
		[2]string{"dotenv-path", `^[^\s]*\.env$`},
	)})
	cases := []map[string]any{
		{"tool_name": "Grep", "tool_input": map[string]any{"pattern": "rm -rf", "path": "."}},
		{"tool_name": "Grep", "tool_input": map[string]any{"pattern": "DROP TABLE", "path": "."}},
		{"tool_name": "Glob", "tool_input": map[string]any{"pattern": "**/.env"}},
	}
	for _, in := range cases {
		input, _ := json.Marshal(in)
		if r := e.evaluate(input); r.Decision != "allow" {
			t.Errorf("%v: got %+v, want allow", in, r)
		}
	}
	writes := []map[string]any{
		{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/tmp/s.sh", "content": "rm -rf /"}},
		{"tool_name": "Edit", "tool_input": map[string]any{"file_path": "/tmp/q.sql", "old_string": "a", "new_string": "DROP TABLE users"}},
		{"tool_name": "Write", "tool_input": map[string]any{"file_path": "/app/.env", "content": "x"}},
	}
	for _, in := range writes {
		input, _ := json.Marshal(in)
		if r := e.evaluate(input); r.Decision != "deny" {
			t.Errorf("%v: got %+v, want deny", in, r)
		}
	}
}

func TestEngine_EvaluateCopilotCLI_StringEncodedToolArgsDeny(t *testing.T) {
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(map[string]any{
		"toolName": "bash",
		"toolArgs": `{"command":"rm -rf /"}`,
	})
	r := e.evaluate(input)
	if r.Decision != "deny" || r.AgentID != "copilot-cli" {
		t.Errorf("got %+v", r)
	}
}

func TestEngine_EvaluateClaudeCode_AgentIDUnaffectedByCopilotFields(t *testing.T) {
	// A Claude Code request never carries toolName/toolArgs, but guard
	// against a future field-name collision silently misclassifying
	// the harness.
	e := newEngine(&Config{Rules: mustRules(t, [2]string{"rm-rf", `rm\s+-rf\b`})})
	input, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": "ls -la"},
		"session_id": "sess-1",
	})
	r := e.evaluate(input)
	if r.AgentID != "claude-code" {
		t.Errorf("AgentID = %q, want claude-code", r.AgentID)
	}
}

func TestEngine_EvaluateInvalidJSON(t *testing.T) {
	e := newEngine(&Config{Rules: []Rule{}})
	if e.evaluate([]byte("not json")).Decision != "allow" {
		t.Error("expected allow on invalid JSON")
	}
}

func TestAllowRuleOverridesDeny(t *testing.T) {
	rules := mustRules(t,
		[2]string{"allow-tmp", `rm\s+-rf\s+/tmp/`},
		[2]string{"deny-rmrf", `rm\s+-rf\b`},
	)
	rules[0].Action = "allow"

	// /tmp path allowed despite matching deny-rmrf
	if m := match("rm -rf /tmp/build", rules); m != nil {
		t.Errorf("expected allow, got deny %q", m.Name)
	}
	// non-/tmp path still denied
	if m := match("rm -rf /home", rules); m == nil || m.Name != "deny-rmrf" {
		t.Errorf("expected deny-rmrf, got %v", m)
	}
}

// ── Config ───────────────────────────────────────────────────────────────

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()
	for _, tc := range []struct{ in, want string }{
		{"~/foo", home + "/foo"},
		{"~", home},
		{"/abs", "/abs"},
		{"rel", "rel"},
	} {
		if got := expandPath(tc.in); got != tc.want {
			t.Errorf("expandPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── DecisionLogger ───────────────────────────────────────────────────────

func TestDecisionLogger(t *testing.T) {
	tmp := t.TempDir() + "/audit.log"
	l := newDecisionLogger(tmp)
	if l == nil {
		t.Fatal("nil logger")
	}
	l.Write(AuditEntry{
		Decision: "deny", Rule: "rm-rf", Tool: "bash",
		Action: "ShellCommand", TrajectoryID: "s1", Content: "rm -rf /",
	})
	l.Close()

	data, _ := os.ReadFile(tmp)
	var entry AuditEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &entry); err != nil {
		t.Fatal(err)
	}
	if entry.Decision != "deny" || entry.Rule != "rm-rf" || entry.TS == "" {
		t.Errorf("got %+v", entry)
	}
}

func TestDecisionLogger_EmptyDisabled(t *testing.T) {
	if newDecisionLogger("") != nil {
		t.Error("expected nil")
	}
}
