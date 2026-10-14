package main

import (
	"os/exec"
	"testing"
)

// TestDemo runs scripts/monitor-demo.sh, which builds this command and
// asserts every step of the documented demo, including a SIGKILL and
// restart of the monitor process.
func TestDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs the monitor as subprocesses")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := exec.Command("bash", "../../scripts/monitor-demo.sh").CombinedOutput()
	t.Logf("demo output:\n%s", out)
	if err != nil {
		t.Fatalf("demo failed: %v", err)
	}
}
