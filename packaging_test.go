package main

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path"
	"reflect"
	"strings"
	"testing"

	imonitor "github.com/Daviey/barmkin/internal/monitor"
)

// TestPackagingUnit holds the shipped systemd unit to the deployment
// `barmkin monitor` requires: a dedicated user, root-created runtime and
// state directories at the monitor's default paths with the modes it
// checks, the client group, and a restart after SIGKILL.
func TestPackagingUnit(t *testing.T) {
	f, err := os.Open("packaging/systemd/barmkin-monitor.service")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	unit := map[string][]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if k, v, ok := strings.Cut(line, "="); ok && !strings.HasPrefix(line, "#") {
			unit[k] = append(unit[k], v)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	one := func(key string) string {
		t.Helper()
		if len(unit[key]) != 1 {
			t.Fatalf("%s is set %d times, want once", key, len(unit[key]))
		}
		return unit[key][0]
	}

	for key, want := range map[string]string{
		"User":                 "barmkin",
		"Group":                imonitor.DefaultClientGroup,
		"RuntimeDirectory":     path.Base(path.Dir(imonitor.DefaultSocket)),
		"RuntimeDirectoryMode": "0750",
		"StateDirectory":       path.Base(imonitor.DefaultStateDir),
		"StateDirectoryMode":   "0700",
		"UMask":                "0077",
		"Restart":              "always",
		"NoNewPrivileges":      "yes",
	} {
		if got := one(key); got != want {
			t.Errorf("%s=%s, want %s", key, got, want)
		}
	}
	if dir := path.Dir(imonitor.DefaultSocket); dir != "/run/"+one("RuntimeDirectory") {
		t.Errorf("the default socket's directory %s is not the unit's RuntimeDirectory", dir)
	}
	if dir := imonitor.DefaultStateDir; dir != "/var/lib/"+one("StateDirectory") {
		t.Errorf("the default state directory %s is not the unit's StateDirectory", dir)
	}
	want := "/usr/local/bin/barmkin monitor -socket " + imonitor.DefaultSocket +
		" -state-dir " + imonitor.DefaultStateDir + " -client-group " + imonitor.DefaultClientGroup
	if got := one("ExecStart"); got != want {
		t.Errorf("ExecStart=%s, want %s", got, want)
	}
}

// TestPackagingRenderSettings checks that packaging/install.sh installs the
// managed-settings recipe unchanged except for the gate, which it pins to
// the monitor's uid, and that it refuses a uid that is not a number.
func TestPackagingRenderSettings(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	out, err := exec.Command("bash", "packaging/install.sh", "render-settings", "--monitor-uid", "4242").Output()
	if err != nil {
		t.Fatalf("render-settings: %v", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("rendered settings are not JSON: %v\n%s", err, out)
	}
	data, err := os.ReadFile("plugins/claude-code/managed-settings.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	gate := want["hooks"].(map[string]any)["PreToolUse"].([]any)[0].(map[string]any)["hooks"].([]any)[0].(map[string]any)
	if gate["command"] != "/usr/local/bin/barmkin gate -socket "+imonitor.DefaultSocket {
		t.Fatalf("recipe gate command %q does not use the default socket", gate["command"])
	}
	gate["command"] = gate["command"].(string) + " -monitor-uid 4242"
	if !reflect.DeepEqual(got, want) {
		t.Errorf("rendered settings differ from the recipe with a pinned gate:\n%s", out)
	}

	if out, err := exec.Command("bash", "packaging/install.sh", "render-settings", "--monitor-uid", "barmkin").CombinedOutput(); err == nil {
		t.Errorf("render-settings accepted a non-numeric uid:\n%s", out)
	}
}
