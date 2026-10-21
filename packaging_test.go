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

	"github.com/Daviey/barmkin/internal/jevproxy"
	imonitor "github.com/Daviey/barmkin/internal/monitor"
)

// TestPackagingUnit holds the shipped systemd unit to the deployment
// `barmkin monitor` requires: a dedicated user, root-created runtime and
// state directories at the monitor's default paths with the modes it
// checks, the client group, and a restart after SIGKILL.
func TestPackagingUnit(t *testing.T) {
	unit := readUnit(t, "packaging/systemd/barmkin-monitor.service")
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
	// The default deployment has no administrative socket.
	if strings.Contains(want, "admin") || unit["Sockets"] != nil {
		t.Errorf("the monitor unit opts in to the administrative socket: %v", unit)
	}
}

// readUnit returns a systemd unit file's settings, key to values.
func readUnit(t *testing.T, path string) map[string][]string {
	t.Helper()
	f, err := os.Open(path)
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
	return unit
}

// TestPackagingAdminSocket holds the opt-in administrative socket to what
// the monitor checks: systemd creates it root's, 0600, in a root directory
// no one else can enter, at the default path monitor-admin uses, and passes
// it under the name the monitor looks for. The drop-in runs the base unit's
// command with -admin-socket and nothing else changed.
func TestPackagingAdminSocket(t *testing.T) {
	sock := readUnit(t, "packaging/systemd/barmkin-monitor-admin.socket")
	for key, want := range map[string]string{
		"ListenStream":       imonitor.DefaultAdminSocket,
		"SocketUser":         "root",
		"SocketGroup":        "root",
		"SocketMode":         "0600",
		"DirectoryMode":      "0700",
		"FileDescriptorName": imonitor.AdminFDName,
		"Service":            "barmkin-monitor.service",
	} {
		if got := sock[key]; len(got) != 1 || got[0] != want {
			t.Errorf("socket %s=%v, want %s", key, got, want)
		}
	}
	if sock["WantedBy"] != nil {
		t.Errorf("the socket is enabled on its own (WantedBy=%v); only the drop-in may pull it in", sock["WantedBy"])
	}

	base := readUnit(t, "packaging/systemd/barmkin-monitor.service")["ExecStart"][0]
	dropin := readUnit(t, "packaging/systemd/barmkin-monitor-admin.conf")
	if want := []string{"", base + " -admin-socket " + imonitor.DefaultAdminSocket}; !reflect.DeepEqual(dropin["ExecStart"], want) {
		t.Errorf("drop-in ExecStart=%q, want %q", dropin["ExecStart"], want)
	}
	for _, key := range []string{"Requires", "After", "Sockets"} {
		if got := dropin[key]; len(got) != 1 || got[0] != "barmkin-monitor-admin.socket" {
			t.Errorf("drop-in %s=%v, want barmkin-monitor-admin.socket", key, got)
		}
	}
	if len(dropin) != 4 {
		t.Errorf("the drop-in changes more than the socket and the command: %v", dropin)
	}
}

// TestPackagingJevProxyUnit holds the shipped Jev proxy unit to the
// deployment `barmkin jev-proxy` requires: it runs as root (no User=), at
// the proxy's default socket, key path and caller group, in a root-created
// runtime directory, with no credential or secret-like key in the unit
// itself, and a restart after a crash.
func TestPackagingJevProxyUnit(t *testing.T) {
	unit := readUnit(t, "packaging/systemd/barmkin-jevproxy.service")
	one := func(key string) string {
		t.Helper()
		if len(unit[key]) != 1 {
			t.Fatalf("%s is set %d times, want once", key, len(unit[key]))
		}
		return unit[key][0]
	}

	if _, ok := unit["User"]; ok {
		t.Errorf("the unit sets User=%v; it must run as root to read the 0600 key file", unit["User"])
	}
	for key, want := range map[string]string{
		"RuntimeDirectory":     path.Base(path.Dir(jevproxy.DefaultSocket)),
		"RuntimeDirectoryMode": "0750",
		"UMask":                "0077",
		"Restart":              "always",
		"NoNewPrivileges":      "yes",
	} {
		if got := one(key); got != want {
			t.Errorf("%s=%s, want %s", key, got, want)
		}
	}
	if dir := path.Dir(jevproxy.DefaultSocket); dir != "/run/"+one("RuntimeDirectory") {
		t.Errorf("the default socket's directory %s is not the unit's RuntimeDirectory", dir)
	}
	want := "/usr/local/bin/barmkin jev-proxy -socket " + jevproxy.DefaultSocket +
		" -key " + jevproxy.DefaultKeyPath + " -caller-group " + jevproxy.DefaultCallerGroup
	if got := one("ExecStart"); got != want {
		t.Errorf("ExecStart=%s, want %s", got, want)
	}
	if got := one("ConditionPathExists"); got != jevproxy.DefaultKeyPath {
		t.Errorf("ConditionPathExists=%s, want the default key path %s", got, jevproxy.DefaultKeyPath)
	}
	for _, key := range []string{"Environment", "LoadCredential", "SetCredential"} {
		if unit[key] != nil {
			t.Errorf("unit sets %s, which must never carry a key: %v", key, unit[key])
		}
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
