// Engine - per-invocation evaluation core.
//
// Each `barmkin eval` call creates one Engine, evaluates one request,
// records telemetry (log + OTel), and closes. There is no persistent
// state between invocations - stats are derived from the log file.

package main

import (
	"encoding/json"
	"time"
)

// Engine holds the compiled config and optional telemetry sinks.
// Created fresh per process invocation.
type Engine struct {
	cfg  *Config
	otel *OTLPExporter
	log  *DecisionLogger
}

// newEngine compiles telemetry sinks from config. Both otel and log
// are nil when their respective config sections are empty/disabled.
func newEngine(cfg *Config) *Engine {
	return &Engine{
		cfg:  cfg,
		otel: newOTLPExporter(cfg.OTel),
		log:  newDecisionLogger(cfg.Log.Path),
	}
}

// evaluate deserializes a JSON request, normalizes Claude Code fields
// into AdapterRequest fields, matches against all rules, and records
// the decision to log/OTel. Returns the HookOutput for the caller.
//
// Invalid JSON fails open (returns allow) so a malformed request
// never blocks productive work.
func (e *Engine) evaluate(input []byte) HookOutput {
	start := time.Now()

	var req Request
	if err := json.Unmarshal(input, &req); err != nil {
		e.record(Request{}, HookOutput{Decision: "allow", Reason: "invalid JSON (failing open)"}, "", start)
		return HookOutput{Decision: "allow", Reason: "invalid JSON (failing open)"}
	}

	req.normalize()
	content := req.extractContent()
	matched := match(content, e.cfg.Rules)

	var result HookOutput
	if matched != nil {
		result = HookOutput{Decision: "deny", Rule: matched.Name, Reason: matched.Reason}
	} else {
		result = HookOutput{Decision: "allow"}
	}

	e.record(req, result, content, start)
	return result
}

// record writes the decision to the audit log and/or OTel exporter.
// Called once per evaluation. Content is redacted, then truncated for
// log readability. Redacting first means a secret that straddles the
// truncation point never leaves a prefix behind in the log.
func (e *Engine) record(req Request, result HookOutput, content string, start time.Time) {
	elapsed := time.Since(start)

	entry := AuditEntry{
		TrajectoryID: req.TrajectoryID,
		Tool:         req.Tool,
		Action:       req.Action,
		Decision:     result.Decision,
		Reason:       result.Reason,
		DurationMs:   float64(elapsed.Microseconds()) / 1000.0,
		Rule:         result.Rule,
		Content:      truncate(redactSecrets(content, e.cfg.Rules), 80),
		Agent:        req.AgentID,
	}

	if e.otel != nil {
		e.otel.Record(entry, start)
	}

	if e.log != nil {
		e.log.Write(entry)
	}
}

// close flushes any remaining telemetry data. Safe to call on a nil
// otel/log since both Flush and Close handle nil receivers.
func (e *Engine) close() {
	if e.otel != nil {
		e.otel.Flush()
	}
	if e.log != nil {
		e.log.Close()
	}
}

// redactSecrets replaces every match of a secret rule in s with
// "[REDACTED:<rule>]". The rules come from the loaded config, so a
// secret rule added there is redacted from the log as well as blocked.
func redactSecrets(s string, rules []Rule) string {
	for _, r := range rules {
		if r.Secret {
			s = r.regex.ReplaceAllLiteralString(s, "[REDACTED:"+r.Name+"]")
		}
	}
	return s
}
