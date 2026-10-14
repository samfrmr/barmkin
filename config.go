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
	Rules []Rule `yaml:"rules"`
	OTel  OTel   `yaml:"otel"`
	Log   Log    `yaml:"log"`
}

// Rule defines a single guardrail pattern.
type Rule struct {
	Name    string `yaml:"name"`    // human-readable identifier (must be unique)
	Pattern string `yaml:"pattern"` // Go regex (re2) matched against command content
	Action  string `yaml:"action"`  // "deny" (default) or "allow" (exempts deny matches inside its own match)
	Reason  string `yaml:"reason"`  // shown to the LLM when denied
	Secret  bool   `yaml:"secret"`  // matches are redacted from the audit log
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
	return &cfg, nil
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
