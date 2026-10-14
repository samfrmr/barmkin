package monitor

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Daviey/barmkin/internal/proto"
)

func post(t *testing.T, c *core, path, body string, uid *uint32) (int, []byte) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	if uid != nil {
		r = r.WithContext(withPeer(r.Context(), *uid))
	}
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	return w.Code, w.Body.Bytes()
}

// postCode posts body and returns the error code it was answered with.
func postCode(t *testing.T, c *core, path, body string, uid *uint32) proto.Code {
	t.Helper()
	status, out := post(t, c, path, body, uid)
	return errorCode(t, status, out)
}

// errorCode decodes body as an ErrorResponse and checks status matches it.
func errorCode(t *testing.T, status int, body []byte) proto.Code {
	t.Helper()
	var e proto.ErrorResponse
	if err := proto.Decode(body, &e); err != nil {
		t.Fatalf("not an error response: %s", body)
	}
	if status != e.Error.HTTPStatus() {
		t.Errorf("status %d for %s", status, e.Error)
	}
	return e.Error
}

func TestTransportRejects(t *testing.T) {
	c, _ := testCore(t)
	uid := alice

	var tr struct {
		UnknownPaths []string `json:"unknown_paths"`
	}
	data, err := os.ReadFile(filepath.Join("..", "proto", "testdata", "transport.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &tr); err != nil {
		t.Fatal(err)
	}
	if len(tr.UnknownPaths) == 0 {
		t.Fatal("no unknown paths in the fixture")
	}
	for _, p := range tr.UnknownPaths {
		if code := postCode(t, c, p, `{"version":1}`, &uid); code != proto.CodeBadRequest {
			t.Errorf("%s: %s, want bad_request", p, code)
		}
	}

	r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	r = r.WithContext(withPeer(r.Context(), uid))
	w := httptest.NewRecorder()
	c.ServeHTTP(w, r)
	if code := errorCode(t, w.Code, w.Body.Bytes()); code != proto.CodeBadRequest {
		t.Errorf("GET: %s", code)
	}

	cases := map[string]struct {
		path, body string
		want       proto.Code
	}{
		"query string":     {"/v1/health?x=1", `{"version":1}`, proto.CodeBadRequest},
		"future version":   {"/v1/decide", `{"version":2,"anything":true}`, proto.CodeVersionMismatch},
		"unknown field":    {"/v1/health", `{"version":1,"clear":true}`, proto.CodeBadRequest},
		"oversized body":   {"/v1/health", `{"version":1}` + strings.Repeat(" ", proto.MaxBodyBytes), proto.CodeBadRequest},
		"wrong op's shape": {"/v1/observe", `{"version":1}`, proto.CodeBadRequest},
	}
	for name, tc := range cases {
		if code := postCode(t, c, tc.path, tc.body, &uid); code != tc.want {
			t.Errorf("%s: %s, want %s", name, code, tc.want)
		}
	}

	if code := postCode(t, c, "/v1/health", `{"version":1}`, nil); code != proto.CodeUnavailable {
		t.Errorf("a request with no peer identity: %s, want unavailable", code)
	}
}

// Every valid request in WP-3's fixtures gets a valid answer: its op's
// response or an error response, never anything else.
func TestFixtureRequestsGetValidAnswers(t *testing.T) {
	c, _ := testCore(t)
	uid := alice
	// Register the fixtures' sessions first, so later ops reach the core.
	for _, s := range []struct{ host, session string }{{"claude_code", "sess-a"}, {"opencode", "ses_root"}} {
		body := `{"version":1,"host":"` + s.host + `","session":"` + s.session + `","root":"` + s.session +
			`","fresh":true,"posture":{"sandbox_enabled":true,"allow_all_unix_sockets":false}}`
		if status, out := post(t, c, "/v1/register", body, &uid); status != http.StatusOK {
			t.Fatalf("register %s: %d %s", s.session, status, out)
		}
	}

	files, err := filepath.Glob(filepath.Join("..", "proto", "testdata", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, file := range files {
		var fx struct {
			Op    proto.Op `json:"op"`
			Valid []struct {
				Name    string          `json:"name"`
				Message string          `json:"message"`
				Body    json.RawMessage `json:"body"`
			} `json:"valid"`
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if json.Unmarshal(data, &fx) != nil || fx.Op == "" {
			continue // transport.json
		}
		for _, v := range fx.Valid {
			if v.Message != "request" {
				continue
			}
			seen++
			status, out := post(t, c, fx.Op.Path(), string(v.Body), &uid)
			if status == http.StatusOK {
				resp, _ := proto.NewResponse(fx.Op)
				if err := proto.Decode(out, resp); err != nil {
					t.Errorf("%s %q: invalid response %s", fx.Op, v.Name, out)
				}
				continue
			}
			code := errorCode(t, status, out)
			if code == proto.CodeBadRequest || code == proto.CodeVersionMismatch {
				t.Errorf("%s %q: a valid request was refused as %s", fx.Op, v.Name, code)
			}
		}
	}
	if seen < 10 {
		t.Fatalf("only %d fixture requests found", seen)
	}
}

// Responses never carry anything the request did not: screened windows
// are not echoed, and no response holds free text.
func TestResponsesAreContentFree(t *testing.T) {
	c, j := testCore(t)
	uid := alice
	post(t, c, "/v1/register", `{"version":1,"host":"claude_code","session":"s","root":"s","fresh":true,"posture":{"sandbox_enabled":true,"allow_all_unix_sockets":false}}`, &uid)
	secret := "ghp_" + strings.Repeat("A", 36)
	_, out := post(t, c, "/v1/screen", `{"version":1,"host":"claude_code","session":"s","source":"fetch","windows":["`+secret+`"],"scores":{"injection":0,"credentials":1,"exfiltration":0}}`, &uid)
	if bytes.Contains(out, []byte(secret)) {
		t.Fatalf("screen echoed its window: %s", out)
	}
	for _, r := range j.records {
		b, _ := json.Marshal(r)
		if bytes.Contains(b, []byte(secret)) {
			t.Fatalf("a window reached the journal: %s", b)
		}
	}
}
