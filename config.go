// Config types and YAML loading for barmkin.
//
// The config file (rules.yaml) defines:
//   - rules:   list of regex rules with name, pattern, action, reason, example
//   - otel:    optional OpenTelemetry OTLP endpoint
//   - log:     optional JSON-lines audit log path
//
// Config lookup order (first existing file wins):
//   1. $BARMKIN_CONFIG
//   2. /etc/barmkin/rules.yaml  (system-wide, authoritative)
//   3. ~/.barmkin/rules.yaml    (user fallback)

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the top-level YAML structure.
type Config struct {
	Rules   []Rule  `yaml:"rules"`
	OTel    OTel    `yaml:"otel"`
	Log     Log     `yaml:"log"`
	Dynamic Dynamic `yaml:"dynamic"` // optional; absent block == disabled, byte-identical behaviour
}

// Rule defines a single guardrail pattern.
type Rule struct {
	Name    string `yaml:"name"`    // human-readable identifier (must be unique)
	Pattern string `yaml:"pattern"` // Go regex (re2) matched against command content
	Action  string `yaml:"action"`  // "deny" (default) or "allow" (overrides all denies)
	Reason  string `yaml:"reason"`  // shown to the LLM when denied
	Example string `yaml:"example"` // test string - verified by `go test` and `barmkin validate`
	regex   *regexp.Regexp
}

// OTel configures the optional OTLP trace exporter.
type OTel struct {
	Endpoint string `yaml:"endpoint"` // OTLP endpoint, e.g. "localhost:4317"
	Service  string `yaml:"service"`  // service name (default "barmkin")
}

// Log configures the optional JSON-lines audit log.
type Log struct {
	Path string `yaml:"path"` // expanded with ~ → $HOME
}

// Dynamic configures the optional second-stage Jev semantic layer.
// See data/barmkin-dynamic-hooks/report.md §5(b) for the full design;
// this is the scoped-down demo subset (System One client, bash-only
// gating, a two-question set, shadow/enforce, a per-session breaker).
type Dynamic struct {
	Enabled bool   `yaml:"enabled"` // master switch; absent block == false
	Mode    string `yaml:"mode"`    // "shadow" (log would-be outcome, always pass) | "enforce"

	Provider DynamicProvider `yaml:"provider"`
	Gate     DynamicGate     `yaml:"gate"`

	OnUnavailable       string            `yaml:"on_unavailable"`         // pass | escalate | deny (default: pass)
	OnUnavailableByMode map[string]string `yaml:"on_unavailable_by_mode"` // per Claude Code permission_mode override

	Breaker DynamicBreaker `yaml:"breaker"`

	Thresholds map[string]float64 `yaml:"thresholds"` // override defaultQuestions[*].RejectAt by question id
}

// DynamicProvider is the System One wire-format endpoint and credential.
// base_url may be an internal gateway in front of a self-hosted model
// (Tier A - the target posture once the model is hosted inside the
// corporate boundary) or a direct provider (OpenRouter/TypeSafe/Vercel
// - Tier B, now treated as an isolated-testing fallback). The gateway
// must itself speak the System One wire format, or needs a format
// adapter in front of it - see demo/README.md's open item.
type DynamicProvider struct {
	BaseURL   string      `yaml:"base_url"` // internal gateway (Tier A) or a direct provider (Tier B fallback)
	Model     string      `yaml:"model"`    // pin a version, e.g. "jev-1.13"; never an alias in enforce mode
	Auth      DynamicAuth `yaml:"auth"`
	TimeoutMs int         `yaml:"timeout_ms"` // hard deadline for the whole dynamic stage (default 1500)
	Redact    string      `yaml:"redact"`     // "default" (apply built-in redaction before egress) | "off" (skip - e.g. data never leaves the corporate boundary via an internal gateway)
}

// DynamicAuth is the credential source for the Jev bearer token.
type DynamicAuth struct {
	Type    string   `yaml:"type"`    // bearer_file (default) | bearer_env | command | none
	Path    string   `yaml:"path"`    // bearer_file: must be 0600, owned by the user; never inside rules.yaml
	Env     string   `yaml:"env"`     // bearer_env: discouraged, visible to the agent's own Bash tool
	Command []string `yaml:"command"` // command: argv of a workload-identity/corp-token broker; stdout (trimmed) is the bearer token
}

// DynamicGate controls which calls reach the dynamic layer at all.
type DynamicGate struct {
	Tools           []string `yaml:"tools"`            // normalized tool names (default: ["bash"])
	PermissionModes []string `yaml:"permission_modes"` // Claude Code permission_mode values that gate (default: auto/bypassPermissions/dontAsk)
	SkipReadOnly    bool     `yaml:"skip_read_only"`   // built-in read-only fast path, per && ; | segment
	SkipAllowRules  bool     `yaml:"skip_allow_rules"` // a matching regex allow rule bypasses the dynamic layer (D6)
}

// DynamicBreaker is the per-session circuit breaker that emulates
// "manual mode" while Jev is unavailable: it can only make Barmkin
// stricter, never loosen a verdict, so tampering with or deleting its
// state file only triggers a fresh probe.
type DynamicBreaker struct {
	Enabled           bool `yaml:"enabled"`
	OpenAfterFailures int  `yaml:"open_after_failures"` // consecutive unavailable results that open the breaker (default 1)
	CooldownS         int  `yaml:"cooldown_s"`          // re-probe Jev after this long (default 60)
}

// applyDefaults fills in the documented defaults for an enabled dynamic
// block. A disabled block (the zero value) is left untouched so the
// zero-config path never even looks at these fields.
func (d *Dynamic) applyDefaults() {
	if !d.Enabled {
		return
	}
	if d.Mode == "" {
		d.Mode = "shadow"
	}
	if d.Provider.TimeoutMs <= 0 {
		d.Provider.TimeoutMs = 1500
	}
	if d.Provider.Auth.Type == "" {
		d.Provider.Auth.Type = "bearer_file"
	}
	if d.Provider.Redact == "" {
		d.Provider.Redact = "default"
	}
	if d.OnUnavailable == "" {
		d.OnUnavailable = "pass"
	}
	if d.Breaker.OpenAfterFailures <= 0 {
		d.Breaker.OpenAfterFailures = 1
	}
	if d.Breaker.CooldownS <= 0 {
		d.Breaker.CooldownS = 60
	}
	if len(d.Gate.Tools) == 0 {
		d.Gate.Tools = []string{"bash"}
	}
	if len(d.Gate.PermissionModes) == 0 {
		d.Gate.PermissionModes = []string{"auto", "bypassPermissions", "dontAsk"}
	}
}

// validateDynamicAuth prints a `barmkin validate` warning if the
// bearer_file credential is missing or not 0600. It never prints the
// key itself, only its source and permissions.
func validateDynamicAuth(auth DynamicAuth) {
	switch auth.Type {
	case "bearer_file", "":
		path := expandPath(auth.Path)
		info, err := os.Stat(path)
		if err != nil {
			fmt.Printf("  ⚠ dynamic.provider.auth: key file %s: %v\n", auth.Path, err)
			return
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			fmt.Printf("  ⚠ dynamic.provider.auth: key file %s has mode %#o, want 0600\n", auth.Path, perm)
			return
		}
		fmt.Printf("  ✓ dynamic.provider.auth: bearer_file %s (0600)\n", auth.Path)
	case "bearer_env":
		if os.Getenv(auth.Env) == "" {
			fmt.Printf("  ⚠ dynamic.provider.auth: env %s is unset\n", auth.Env)
			return
		}
		fmt.Printf("  ✓ dynamic.provider.auth: bearer_env %s (set)\n", auth.Env)
	case "command":
		if len(auth.Command) == 0 {
			fmt.Println("  ⚠ dynamic.provider.auth: command is empty")
			return
		}
		fmt.Printf("  ✓ dynamic.provider.auth: command %v (workload identity / corp token broker)\n", auth.Command)
	case "none":
		fmt.Println("  ✓ dynamic.provider.auth: none (gateway does auth)")
	}
}

// dynamicStatus returns a human-readable summary for `barmkin validate`.
func dynamicStatus(d Dynamic) string {
	if !d.Enabled {
		return "disabled"
	}
	return fmt.Sprintf("%s (provider=%s, model=%s, on_unavailable=%s, redact=%s)",
		d.Mode, d.Provider.BaseURL, d.Provider.Model, d.OnUnavailable, d.Provider.Redact)
}

// compile validates the regex pattern and defaults Action to "deny".
func (r *Rule) compile() error {
	re, err := regexp.Compile(r.Pattern)
	if err != nil {
		return err
	}
	r.regex = re
	if r.Action == "" {
		r.Action = "deny"
	}
	return nil
}

// loadConfig reads and parses the YAML config file, compiles all rule
// regexes, and expands ~ in the log path.
func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	cfg.Log.Path = expandPath(cfg.Log.Path)
	for i := range cfg.Rules {
		if err := cfg.Rules[i].compile(); err != nil {
			return nil, fmt.Errorf("rule %q: %w", cfg.Rules[i].Name, err)
		}
	}
	cfg.Dynamic.applyDefaults()
	applyDynamicKillSwitch(&cfg.Dynamic)
	return &cfg, nil
}

// applyDynamicKillSwitch implements D7: BARMKIN_DYNAMIC=off can only
// turn the dynamic layer off, never on. Any other value (including
// "on") is ignored, so a config that doesn't enable the layer can't be
// enabled by environment alone - only /etc/barmkin/rules.yaml can do
// that (report.md §5b).
func applyDynamicKillSwitch(d *Dynamic) {
	if os.Getenv("BARMKIN_DYNAMIC") == "off" {
		d.Enabled = false
	}
}

// otelStatus returns a human-readable OTel status string for `barmkin validate`.
func otelStatus(o OTel) string {
	if o.Endpoint == "" {
		return "disabled"
	}
	if o.Service == "" {
		return fmt.Sprintf("%s (service=barmkin)", o.Endpoint)
	}
	return fmt.Sprintf("%s (service=%s)", o.Endpoint, o.Service)
}

// logStatus returns a human-readable log status string for `barmkin validate`.
func logStatus(l Log) string {
	if l.Path == "" {
		return "disabled"
	}
	return l.Path
}

// defaultConfigPath resolves the config file location using the lookup order.
func defaultConfigPath() string {
	for _, p := range []string{
		os.Getenv("BARMKIN_CONFIG"),
		"/etc/barmkin/rules.yaml",
		filepath.Join(homeDir(), ".barmkin", "rules.yaml"),
	} {
		if p != "" && fileExists(p) {
			return p
		}
	}
	return filepath.Join(homeDir(), ".barmkin", "rules.yaml")
}

// expandPath replaces a leading ~ with the user's home directory.
func expandPath(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(homeDir(), p[2:])
	}
	if p == "~" {
		return homeDir()
	}
	return p
}

func homeDir() string {
	h, _ := os.UserHomeDir()
	return h
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
