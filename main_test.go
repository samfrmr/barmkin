package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn and returns
// what it wrote. Used for cmdDynamicStatus, whose contract is its
// printed line (consumed by the opencode plugin's own stdout read).
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	w.Close()
	os.Stdout = orig

	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String()
}

func TestCmdDynamicStatus_Enabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("dynamic:\n  enabled: true\n  mode: shadow\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := captureStdout(t, func() { cmdDynamicStatus(path) })
	if got != "enabled\n" {
		t.Errorf("got %q, want %q", got, "enabled\n")
	}
}

func TestCmdDynamicStatus_Disabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	if err := os.WriteFile(path, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := captureStdout(t, func() { cmdDynamicStatus(path) })
	if got != "disabled\n" {
		t.Errorf("got %q, want %q", got, "disabled\n")
	}
}

func TestCmdDynamicStatus_ConfigErrorFailsSafeToDisabled(t *testing.T) {
	got := captureStdout(t, func() { cmdDynamicStatus(filepath.Join(t.TempDir(), "missing.yaml")) })
	if got != "disabled\n" {
		t.Errorf("got %q, want %q", got, "disabled\n")
	}
}

func writeLogLines(t *testing.T, lines ...AuditEntry) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	l := newDecisionLogger(path)
	if l == nil {
		t.Fatal("nil logger")
	}
	for _, e := range lines {
		l.Write(e)
	}
	l.Close()
	return path
}

func TestComputeStats_CountsEscalateSeparatelyFromAllow(t *testing.T) {
	path := writeLogLines(t,
		AuditEntry{Decision: "allow"},
		AuditEntry{Decision: "allow"},
		AuditEntry{Decision: "escalate"},
		AuditEntry{Decision: "deny", Rule: "rm-rf-force"},
	)

	sum, err := computeStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Events != 4 {
		t.Errorf("events = %d, want 4", sum.Events)
	}
	if sum.Allows != 2 {
		t.Errorf("allows = %d, want 2 (escalate must not be folded into allow - the pre-fix main.go:285-91 bug)", sum.Allows)
	}
	if sum.Escalates != 1 {
		t.Errorf("escalates = %d, want 1", sum.Escalates)
	}
	if sum.Denies != 1 {
		t.Errorf("denies = %d, want 1", sum.Denies)
	}
	if sum.Hits["rm-rf-force"] != 1 {
		t.Errorf("hits[rm-rf-force] = %d, want 1", sum.Hits["rm-rf-force"])
	}
}

func TestComputeStats_DynamicFields(t *testing.T) {
	path := writeLogLines(t,
		AuditEntry{Decision: "allow", Layer: "dynamic", Dynamic: &DynamicAudit{Outcome: "allow", LatencyMs: 100}},
		AuditEntry{Decision: "escalate", Layer: "dynamic", Dynamic: &DynamicAudit{Outcome: "escalate", LatencyMs: 300}},
		AuditEntry{Decision: "escalate", Layer: "dynamic", Dynamic: &DynamicAudit{Outcome: "escalate", Error: "timeout", FailMode: "on_unavailable"}},
		// a regex-only decision (no dynamic layer) must not count as a dynamic event
		AuditEntry{Decision: "deny", Rule: "rm-rf-force"},
	)

	sum, err := computeStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.DynamicEvents != 3 {
		t.Errorf("dynamicEvents = %d, want 3", sum.DynamicEvents)
	}
	if sum.DynamicUnavailable != 1 {
		t.Errorf("dynamicUnavailable = %d, want 1", sum.DynamicUnavailable)
	}
	if sum.DynamicOutcomes["escalate"] != 2 {
		t.Errorf("dynamicOutcomes[escalate] = %d, want 2", sum.DynamicOutcomes["escalate"])
	}
	if !sum.HasLatency || sum.LatencyP50 <= 0 {
		t.Errorf("expected latency percentiles from the two latency-bearing entries, got %+v", sum)
	}
}

func TestComputeStats_NoLogFile(t *testing.T) {
	if _, err := computeStats(filepath.Join(t.TempDir(), "missing.log")); err == nil {
		t.Error("expected an error for a missing log file")
	}
}

func TestComputeStats_MalformedLinesSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("not json\n{\"decision\":\"allow\"}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sum, err := computeStats(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Events != 1 {
		t.Errorf("events = %d, want 1 (malformed line skipped)", sum.Events)
	}
}

func TestLatencyPercentiles_Empty(t *testing.T) {
	if _, _, ok := latencyPercentiles(nil); ok {
		t.Error("expected ok=false for empty input")
	}
}

func TestLatencyPercentiles_Basic(t *testing.T) {
	p50, p95, ok := latencyPercentiles([]float64{100, 200, 300, 400, 500})
	if !ok {
		t.Fatal("expected ok=true")
	}
	if p50 != 300 {
		t.Errorf("p50 = %v, want 300", p50)
	}
	if p95 != 500 {
		t.Errorf("p95 = %v, want 500", p95)
	}
}
