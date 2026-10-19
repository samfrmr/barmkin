package admin

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daviey/barmkin/internal/proto"
)

const validClear = `{"version":1,"uid":1000,"host":"claude_code","lineage":"root","epoch":0,"legs":{"untrusted":"fetch","sensitive":"none"},"reason":"reviewed_safe"}`

func TestDecodeClearIsStrict(t *testing.T) {
	var ok ClearRequest
	if err := Decode([]byte(validClear), MaxRequestBytes, &ok); err != nil {
		t.Fatalf("valid clear: %v", err)
	}
	bad := map[string]string{
		"free-text reason":  strings.Replace(validClear, `"reviewed_safe"`, `"user asked nicely"`, 1),
		"empty reason":      strings.Replace(validClear, `"reviewed_safe"`, `""`, 1),
		"missing reason":    strings.Replace(validClear, `,"reason":"reviewed_safe"`, ``, 1),
		"null legs":         strings.Replace(validClear, `{"untrusted":"fetch","sensitive":"none"}`, `null`, 1),
		"missing leg":       strings.Replace(validClear, `"untrusted":"fetch",`, ``, 1),
		"unknown field":     strings.Replace(validClear, `"epoch":0`, `"epoch":0,"all":true`, 1),
		"bad host":          strings.Replace(validClear, `claude_code`, `copilot`, 1),
		"bad lineage":       strings.Replace(validClear, `"root"`, `"has space"`, 1),
		"wrong version":     strings.Replace(validClear, `"version":1`, `"version":2`, 1),
		"leg mismatch":      strings.Replace(validClear, `"untrusted":"fetch"`, `"untrusted":"credential"`, 1),
		"trailing value":    validClear + `{}`,
		"negative uid":      strings.Replace(validClear, `"uid":1000`, `"uid":-1`, 1),
		"too large":         strings.Replace(validClear, `"root"`, `"`+strings.Repeat("r", MaxRequestBytes)+`"`, 1),
		"array":             `[` + validClear + `]`,
		"lineage wildcards": strings.Replace(validClear, `"root"`, `"*"`, 1),
	}
	for name, body := range bad {
		var req ClearRequest
		if err := Decode([]byte(body), MaxRequestBytes, &req); err == nil {
			t.Errorf("%s: decoded %+v", name, req)
		}
	}
}

func TestPathsNeverOverlapTheClientContract(t *testing.T) {
	for _, op := range Ops {
		if _, ok := proto.ParsePath(op.Path()); ok {
			t.Errorf("%s is also a client operation", op.Path())
		}
		if got, ok := ParsePath(op.Path()); !ok || got != op {
			t.Errorf("%s does not parse back", op.Path())
		}
	}
	for _, op := range proto.Ops {
		if _, ok := ParsePath(op.Path()); ok {
			t.Errorf("client operation %s is an administrative path", op.Path())
		}
	}
	for _, p := range []string{"/admin/v1/clear/", "/admin/v1/", "/admin/v2/clear", "/admin/v1/Clear", "/v1/clear"} {
		if _, ok := ParsePath(p); ok {
			t.Errorf("%s parsed", p)
		}
	}
}

func TestCheckSocket(t *testing.T) {
	uid := os.Getuid()
	setup := func(t *testing.T, dirMode, sockMode os.FileMode) string {
		t.Helper()
		base, err := os.MkdirTemp("", "bma")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.RemoveAll(base) })
		dir := filepath.Join(base, "admin")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "admin.sock")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { ln.Close() })
		if err := os.Chmod(path, sockMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, dirMode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := CheckSocket(setup(t, 0o700, 0o600), uid); err != nil {
		t.Errorf("a private socket: %v", err)
	}
	for name, path := range map[string]string{
		"socket others can connect to": setup(t, 0o700, 0o666),
		"directory others can enter":   setup(t, 0o711, 0o600),
		"group-readable directory":     setup(t, 0o750, 0o600),
	} {
		if err := CheckSocket(path, uid); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if uid != 0 {
		if err := CheckSocket(setup(t, 0o700, 0o600), 0); err == nil {
			t.Error("a socket another uid owns: accepted as root's")
		}
	}
	file := filepath.Join(t.TempDir(), "admin.sock")
	os.WriteFile(file, nil, 0o600)
	if err := CheckSocket(file, uid); err == nil {
		t.Error("a regular file: accepted")
	}
	path := setup(t, 0o700, 0o600)
	link := filepath.Join(filepath.Dir(path), "link.sock")
	os.Symlink(path, link)
	if err := CheckSocket(link, uid); err == nil {
		t.Error("a symlink: accepted")
	}
	if err := CheckSocket("admin.sock", uid); err == nil {
		t.Error("a relative path: accepted")
	}
}
