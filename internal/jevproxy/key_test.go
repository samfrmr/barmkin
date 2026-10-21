package jevproxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withOwnUID points wantKeyUID at the test process's own uid for the
// duration of the test, since tests cannot create a file owned by uid 0
// without being root.
func withOwnUID(t *testing.T) {
	t.Helper()
	old := wantKeyUID
	wantKeyUID = os.Getuid()
	t.Cleanup(func() { wantKeyUID = old })
}

func writeKey(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "jev-openrouter.key")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadKey(t *testing.T) {
	withOwnUID(t)
	path := writeKey(t, "sk-or-v1-abc123\n", 0o600)
	secret, err := LoadKey(path)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if secret.Value() != "sk-or-v1-abc123" {
		t.Errorf("key = %q, want trimmed content", secret.Value())
	}
}

func TestLoadKeyRedacts(t *testing.T) {
	withOwnUID(t)
	path := writeKey(t, "sk-or-v1-verysecret", 0o600)
	secret, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{
		secret.String(),
		fmt.Sprintf("%v", secret),
		fmt.Sprintf("%+v", secret),
		fmt.Sprintf("%s", secret),
	} {
		if strings.Contains(rendered, "verysecret") {
			t.Errorf("secret leaked through formatting: %q", rendered)
		}
		if rendered != redacted {
			t.Errorf("rendered = %q, want %q", rendered, redacted)
		}
	}
}

func TestLoadKeyRefuses(t *testing.T) {
	withOwnUID(t)
	cases := map[string]func(t *testing.T) string{
		"missing": func(t *testing.T) string {
			return filepath.Join(t.TempDir(), "absent.key")
		},
		"group readable": func(t *testing.T) string {
			return writeKey(t, "sk-or-v1-x", 0o640)
		},
		"world readable": func(t *testing.T) string {
			return writeKey(t, "sk-or-v1-x", 0o604)
		},
		"empty": func(t *testing.T) string {
			return writeKey(t, "", 0o600)
		},
		"whitespace only": func(t *testing.T) string {
			return writeKey(t, "   \n\t  ", 0o600)
		},
		"embedded newline": func(t *testing.T) string {
			return writeKey(t, "sk-or-v1-a\nsk-or-v1-b", 0o600)
		},
		"directory": func(t *testing.T) string {
			return t.TempDir()
		},
		"symlink": func(t *testing.T) string {
			real := writeKey(t, "sk-or-v1-x", 0o600)
			link := real + ".link"
			if err := os.Symlink(real, link); err != nil {
				t.Fatal(err)
			}
			return link
		},
		"not owned by the pinned uid": func(t *testing.T) string {
			old := wantKeyUID
			wantKeyUID = os.Getuid() + 999999
			t.Cleanup(func() { wantKeyUID = old })
			return writeKey(t, "sk-or-v1-x", 0o600)
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			path := setup(t)
			if _, err := LoadKey(path); err == nil {
				t.Fatalf("LoadKey(%s) succeeded, want an error", name)
			}
		})
	}
}
