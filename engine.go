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
		e.record(Request{}, HookOutput{Decision: "allow", Reason: "invalid JSON (failing open)"}, "", start, nil)
		return HookOutput{Decision: "allow", Reason: "invalid JSON (failing open)"}
	}

	req.normalize()
	content := req.extractContent()
	var matched *Rule
	for _, target := range req.scanTargets() {
		if matched = match(target, e.cfg.Rules); matched != nil {
			break
		}
	}

	var result HookOutput
	var dyn *dynamicResult
	if matched != nil {
		// Regex deny: the dynamic layer never sees this, and Jev is
		// never called - a regex deny is final (monotonicity).
		result = HookOutput{Decision: "deny", Rule: matched.Name, Reason: matched.Reason}
	} else {
		result = HookOutput{Decision: "allow"}
		if e.cfg.Dynamic.Enabled {
			allowMatched := matchedAllowRule(content, e.cfg.Rules)
			if e.cfg.Dynamic.shouldGate(req, content, allowMatched) {
				dyn = runDynamic(e.cfg.Dynamic, req, content)
				result = dyn.toHookOutput()
			}
		}
	}

	e.record(req, result, content, start, dyn)
	result.AgentID = req.AgentID
	return result
}

// record writes the decision to the audit log and/or OTel exporter.
// Called once per evaluation. Content is truncated for log readability.
// dyn is non-nil only when the dynamic layer ran, in which case the
// log line gains the "layer", "permission_mode" and "dynamic" fields;
// a nil dyn (the zero-config/disabled path) produces a byte-identical
// line to before the dynamic layer existed.
func (e *Engine) record(req Request, result HookOutput, content string, start time.Time, dyn *dynamicResult) {
	elapsed := time.Since(start)

	entry := AuditEntry{
		TrajectoryID: req.TrajectoryID,
		Tool:         req.Tool,
		Action:       req.Action,
		Decision:     result.Decision,
		Reason:       result.Reason,
		DurationMs:   float64(elapsed.Microseconds()) / 1000.0,
		Rule:         result.Rule,
		Content:      truncate(content, 80),
		Agent:        req.AgentID,
	}

	if dyn != nil {
		entry.Layer = "dynamic"
		entry.PermissionMode = req.PermissionMode
		entry.Dynamic = dyn.toAudit()
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
