package jevproxy

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// wantKeyUID is the uid the key file must be owned by. It is a var, not a
// constant, only so a test can point it at the test process's own uid; in
// every real deployment the key file is root's.
var wantKeyUID = 0

// LoadKey reads and validates the OpenRouter API key file: a regular file,
// not a symlink, owned by wantKeyUID, with mode exactly 0600 so no other
// user or group can read it. It refuses a missing, empty or
// whitespace-only key. The returned [Secret] is never logged by this
// package; LoadKey itself logs only the path, never the key's content or
// length.
func LoadKey(path string) (Secret, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("jev key %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("jev key %s: not a regular file", path)
	}
	if owner(fi) != wantKeyUID {
		return "", fmt.Errorf("jev key %s: not owned by uid %d", path, wantKeyUID)
	}
	if fi.Mode().Perm() != 0o600 {
		return "", fmt.Errorf("jev key %s: mode %#o, want exactly 0600", path, fi.Mode().Perm())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("jev key %s: %w", path, err)
	}
	key := strings.TrimSpace(string(data))
	if key == "" {
		return "", fmt.Errorf("jev key %s: empty", path)
	}
	if strings.ContainsAny(key, "\r\n") {
		return "", errors.New("jev key: contains a newline after trimming; check the file's content")
	}
	return Secret(key), nil
}
