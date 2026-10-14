package proto

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// The fixtures in testdata are shared with shims/common/proto.test.ts. Each
// <op>.json holds valid messages, which must decode and re-encode to the
// same bytes, and invalid ones, which must fail with the given code.
// transport.json pins the constants and paths both sides use.

type fixtureCase struct {
	Name    string          `json:"name"`
	Message string          `json:"message"` // request, response or error
	Body    json.RawMessage `json:"body"`
	Raw     *string         `json:"raw"` // a body that is not a JSON object
	Error   Code            `json:"error"`
}

type fixtureFile struct {
	Op      Op            `json:"op"`
	Valid   []fixtureCase `json:"valid"`
	Invalid []fixtureCase `json:"invalid"`
}

type transportFixture struct {
	Version          int          `json:"version"`
	PathPrefix       string       `json:"path_prefix"`
	MaxBodyBytes     int          `json:"max_body_bytes"`
	ClientDeadlineMS int64        `json:"client_deadline_ms"`
	Ops              []Op         `json:"ops"`
	UnknownPaths     []string     `json:"unknown_paths"`
	Codes            map[Code]int `json:"codes"`
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

func newMessage(t *testing.T, op Op, kind string) Message {
	t.Helper()
	var m Message
	ok := false
	switch kind {
	case "request":
		m, ok = NewRequest(op)
	case "response":
		m, ok = NewResponse(op)
	case "error":
		m, ok = &ErrorResponse{}, true
	}
	if !ok {
		t.Fatalf("no %s message for op %q", kind, op)
	}
	return m
}

func TestWireFixtures(t *testing.T) {
	var tr transportFixture
	readJSON(t, filepath.Join("testdata", "transport.json"), &tr)
	if tr.Version != Version || tr.PathPrefix != PathPrefix || tr.MaxBodyBytes != MaxBodyBytes ||
		tr.ClientDeadlineMS != ClientDeadline.Milliseconds() {
		t.Errorf("transport constants differ from the package: %+v", tr)
	}
	if !slices.Equal(tr.Ops, Ops) {
		t.Errorf("ops = %v, want %v", tr.Ops, Ops)
	}
	for _, op := range Ops {
		if got, ok := ParsePath(op.Path()); !ok || got != op {
			t.Errorf("ParsePath(%q) = %q, %v", op.Path(), got, ok)
		}
	}
	for _, p := range tr.UnknownPaths {
		if op, ok := ParsePath(p); ok {
			t.Errorf("ParsePath(%q) = %q, want no operation", p, op)
		}
	}
	if len(tr.Codes) != len(Codes) {
		t.Errorf("codes = %v, want one entry per code in %v", tr.Codes, Codes)
	}
	for _, c := range Codes {
		if status, ok := tr.Codes[c]; !ok || status != c.HTTPStatus() {
			t.Errorf("code %q: fixture status %d, HTTPStatus %d", c, status, c.HTTPStatus())
		}
	}

	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var covered []Op
	for _, path := range paths {
		if filepath.Base(path) == "transport.json" {
			continue
		}
		var f fixtureFile
		readJSON(t, path, &f)
		if filepath.Base(path) != string(f.Op)+".json" || !slices.Contains(Ops, f.Op) {
			t.Fatalf("%s: op %q does not match the file or is unknown", path, f.Op)
		}
		covered = append(covered, f.Op)
		kinds := map[string]bool{}

		for _, c := range f.Valid {
			t.Run(string(f.Op)+"/valid/"+c.Name, func(t *testing.T) {
				kinds[c.Message] = true
				m := newMessage(t, f.Op, c.Message)
				if err := Decode(c.Body, m); err != nil {
					t.Fatalf("Decode: %v", err)
				}
				got, err := Encode(m)
				if err != nil {
					t.Fatalf("Encode: %v", err)
				}
				var want bytes.Buffer
				if err := json.Compact(&want, c.Body); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want.Bytes()) {
					t.Errorf("re-encoded\n got %s\nwant %s", got, want.Bytes())
				}
			})
		}
		if !kinds["request"] || !kinds["response"] {
			t.Errorf("%s: needs at least one valid request and one valid response", path)
		}

		for _, c := range f.Invalid {
			t.Run(string(f.Op)+"/invalid/"+c.Name, func(t *testing.T) {
				data := []byte(c.Body)
				if c.Raw != nil {
					data = []byte(*c.Raw)
				}
				err := Decode(data, newMessage(t, f.Op, c.Message))
				var e *Error
				if !errors.As(err, &e) || e.Code != c.Error {
					t.Errorf("Decode error = %v, want code %q", err, c.Error)
				}
			})
		}
	}
	slices.Sort(covered)
	want := slices.Clone(Ops)
	slices.Sort(want)
	if !slices.Equal(covered, want) {
		t.Errorf("fixture files cover %v, want every op in %v", covered, want)
	}
}

// TestTypeScriptFixtures runs the TypeScript side of the same fixtures.
func TestTypeScriptFixtures(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available")
	}
	cmd := exec.Command("node", "--test", "proto.test.ts")
	cmd.Dir = filepath.Join("..", "..", "shims", "common")
	out, err := cmd.CombinedOutput()
	t.Logf("node --test output:\n%s", out)
	if err != nil {
		t.Fatalf("TypeScript fixture tests failed: %v", err)
	}
}

// tokenGrammar is the token shape ValidToken checks, as a regexp.
var tokenGrammar = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// FuzzValidToken holds ValidToken to the token grammar.
func FuzzValidToken(f *testing.F) {
	for _, s := range []string{
		"", "a", "sess-a", "toolu_01A", "a.b_c-D9", "a b", "a\n", "\na", "é", "a/b", "a\x00",
		strings.Repeat("a", 127), strings.Repeat("a", 128), strings.Repeat("a", 129),
		strings.Repeat("é", 64), "-", ".", "_", "A~", "[", "`", "{", "@", ":",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := ValidToken(s), tokenGrammar.MatchString(s); got != want {
			t.Fatalf("ValidToken(%q) = %v, the grammar says %v", s, got, want)
		}
	})
}
