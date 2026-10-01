// Jev System One client.
//
// Jev is a "System One" decision model (TypeSafe). You send `state`
// and typed `questions`; it returns typed answers, not generated text.
// All three access paths (TypeSafe direct, OpenRouter, Vercel AI
// Gateway) serve the same wire format at POST {base_url}/v1/systemone,
// so this client is provider-neutral: base_url, model and the
// credential source are all configuration (Dynamic.Provider).
//
// This client talks to base_url over HTTPS - either an internal
// gateway in front of a self-hosted model (Tier A, the target posture
// once the model is hosted inside the corporate boundary - see D1/D3
// revision 2026-10-01) or a direct provider (OpenRouter/TypeSafe,
// Tier B, kept as an isolated-testing fallback). No corporate egress
// proxy is configured by this client either way; point base_url at
// the gateway and let it enforce network policy.
//
// Jev must never be the component that permits: it answers predefined
// yes/no (Noul) questions with a probability, and composition code
// elsewhere (dynamic.go) turns those probabilities into a Decision.
// This file only fetches and strictly validates the answers.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// jevModelPattern accepts any provider's spelling of a pinned jev-1.13
// response (TypeSafe direct: "jev-1.13.0"; OpenRouter: the mapped
// "typesafe/jev-1.13-20260917"). A bare "jev-latest"/"jev-preview"
// alias in the response is rejected: pin the version.
var jevModelPattern = regexp.MustCompile(`jev-1\.13\b`)

// errRedirect is returned by CheckRedirect to refuse every redirect:
// the bearer token must never follow a 30x to an unexpected host.
var errRedirect = errors.New("jev: redirects are disabled")

// maxJevResponseBytes caps the response body read, so a misbehaving
// or malicious endpoint can't exhaust memory.
const maxJevResponseBytes = 256 * 1024

// jevQuestion is one System One question. The POC only uses "noul"
// (probability-of-yes) questions - never mix Noul and Choice
// thresholds in one composition. TypeSafe's wire format requires both
// type and instructions on every question; instructions may be a
// string, object, or array (criteria is optional).
type jevQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

type systemOneRequest struct {
	Model     string                 `json:"model"`
	State     map[string]string      `json:"state"`
	Questions map[string]jevQuestion `json:"questions"`
}

type systemOneAnswer struct {
	Type string   `json:"type"`
	Noul *float64 `json:"noul,omitempty"`
}

type systemOneUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type systemOneResponse struct {
	Model   string                     `json:"model"`
	Answers map[string]systemOneAnswer `json:"answers"`
	Usage   systemOneUsage             `json:"usage"`
	ID      string                     `json:"id"`
}

// jevError classifies a dynamic-layer failure using the fail-closed
// taxonomy from the reference prior art (pi-jev-auto-mode): every
// kind here degrades through on_unavailable, never through "allow".
type jevError struct {
	kind string // no_key | timeout | network | http_<code> | malformed_response | breaker_open | refused_send
	err  error
}

func (e *jevError) Error() string {
	if e.err != nil {
		return fmt.Sprintf("jev: %s: %v", e.kind, e.err)
	}
	return "jev: " + e.kind
}

func errKind(err error) string {
	var je *jevError
	if errors.As(err, &je) {
		return je.kind
	}
	return "unknown"
}

// jevClient is a provider-neutral System One HTTP client.
type jevClient struct {
	baseURL string
	model   string
	key     string
	client  *http.Client
	timeout time.Duration
}

// newJevClient builds a client from Provider config, resolving the
// bearer credential. Returns a *jevError (kind "no_key") if the
// credential can't be read - this is a normal, expected failure mode
// in the demo (no key configured) and routes through on_unavailable
// like any other transport failure, never panics or falls back to an
// implicit allow.
func newJevClient(cfg DynamicProvider) (*jevClient, error) {
	key, err := resolveJevKey(cfg.Auth)
	if err != nil {
		return nil, err
	}
	timeout := time.Duration(cfg.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	return &jevClient{
		baseURL: strings.TrimSuffix(cfg.BaseURL, "/"),
		model:   cfg.Model,
		key:     key,
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return errRedirect
			},
		},
	}, nil
}

// resolveJevKey reads the bearer credential per auth.type. bearer_file
// requires the file to exist with mode 0600 (D3): any looser
// permission is treated as "no key" rather than silently trusting a
// key any local process could have tampered with or read.
func resolveJevKey(auth DynamicAuth) (string, error) {
	switch auth.Type {
	case "none":
		return "", nil
	case "bearer_env":
		if auth.Env == "" {
			return "", &jevError{kind: "no_key", err: errors.New("auth.env not set")}
		}
		v := os.Getenv(auth.Env)
		if v == "" {
			return "", &jevError{kind: "no_key", err: fmt.Errorf("%s is empty", auth.Env)}
		}
		return v, nil
	case "command":
		// Workload identity / a short-lived token from a corporate
		// broker (Tier A target credential model). stdout (trimmed)
		// is the bearer token; a nonzero exit or empty output is a
		// normal "no_key" failure, routed through on_unavailable like
		// any other transport failure.
		if len(auth.Command) == 0 {
			return "", &jevError{kind: "no_key", err: errors.New("auth.command not set")}
		}
		out, err := exec.Command(auth.Command[0], auth.Command[1:]...).Output()
		if err != nil {
			return "", &jevError{kind: "no_key", err: fmt.Errorf("auth.command: %w", err)}
		}
		token := strings.TrimSpace(string(out))
		if token == "" {
			return "", &jevError{kind: "no_key", err: errors.New("auth.command produced no token")}
		}
		return token, nil
	case "bearer_file", "":
		path := auth.Path
		if path == "" {
			return "", &jevError{kind: "no_key", err: errors.New("auth.path not set")}
		}
		path = expandPath(path)
		info, err := os.Stat(path)
		if err != nil {
			return "", &jevError{kind: "no_key", err: err}
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			return "", &jevError{kind: "no_key", err: fmt.Errorf("key file %s must be mode 0600, has %#o", path, perm)}
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", &jevError{kind: "no_key", err: err}
		}
		key := strings.TrimSpace(string(b))
		if key == "" {
			return "", &jevError{kind: "no_key", err: errors.New("key file is empty")}
		}
		return key, nil
	default:
		return "", &jevError{kind: "no_key", err: fmt.Errorf("unknown auth.type %q", auth.Type)}
	}
}

// ask sends one System One request with all questions evaluated in
// parallel against the same state, and strictly validates the
// response: an HTTP 200 is not yet an answer. Any shape deviation
// (missing/extra answer, wrong type, non-finite or out-of-range noul,
// an unpinned model spelling) is a malformed_response error, not a
// best-effort partial result.
func (c *jevClient) ask(ctx context.Context, state map[string]string, questions map[string]jevQuestion) (probs map[string]float64, modelID, requestID string, err error) {
	reqBody := systemOneRequest{Model: c.model, State: state, Questions: questions}
	body, merr := json.Marshal(reqBody)
	if merr != nil {
		return nil, "", "", &jevError{kind: "network", err: merr}
	}
	// Refuse to send if the body contains the bearer key itself or a
	// PEM private-key marker (pi-jev-guard's hygiene check).
	if (c.key != "" && bytes.Contains(body, []byte(c.key))) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		return nil, "", "", &jevError{kind: "refused_send", err: errors.New("request body contains a credential marker")}
	}

	httpReq, nerr := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/systemone", bytes.NewReader(body))
	if nerr != nil {
		return nil, "", "", &jevError{kind: "network", err: nerr}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.key != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.key)
	}

	resp, derr := c.client.Do(httpReq)
	if derr != nil {
		if errors.Is(derr, context.DeadlineExceeded) || os.IsTimeout(derr) {
			return nil, "", "", &jevError{kind: "timeout", err: derr}
		}
		return nil, "", "", &jevError{kind: "network", err: derr}
	}
	defer resp.Body.Close()

	data, rerr := io.ReadAll(io.LimitReader(resp.Body, maxJevResponseBytes))
	if rerr != nil {
		return nil, "", "", &jevError{kind: "network", err: rerr}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, "", "", &jevError{kind: fmt.Sprintf("http_%d", resp.StatusCode)}
	}

	var sysResp systemOneResponse
	if err := json.Unmarshal(data, &sysResp); err != nil {
		return nil, "", "", &jevError{kind: "malformed_response", err: err}
	}
	if !jevModelPattern.MatchString(sysResp.Model) {
		return nil, "", "", &jevError{kind: "malformed_response", err: fmt.Errorf("unexpected model spelling %q", sysResp.Model)}
	}
	if len(sysResp.Answers) != len(questions) {
		return nil, "", "", &jevError{kind: "malformed_response", err: fmt.Errorf("got %d answers, want %d", len(sysResp.Answers), len(questions))}
	}

	out := make(map[string]float64, len(questions))
	for id := range questions {
		ans, ok := sysResp.Answers[id]
		if !ok {
			return nil, "", "", &jevError{kind: "malformed_response", err: fmt.Errorf("missing answer %q", id)}
		}
		if ans.Type != "noul" || ans.Noul == nil {
			return nil, "", "", &jevError{kind: "malformed_response", err: fmt.Errorf("answer %q: not a valid noul", id)}
		}
		p := *ans.Noul
		if math.IsNaN(p) || math.IsInf(p, 0) || p < 0 || p > 1 {
			return nil, "", "", &jevError{kind: "malformed_response", err: fmt.Errorf("answer %q: noul %v out of range", id, p)}
		}
		out[id] = p
	}

	return out, sysResp.Model, sysResp.ID, nil
}

// secretPatterns are redacted from any text before it is sent to Jev.
// Taken from pi-jev-guard's redaction set (D2: command text + cwd
// only, never file contents).
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`), // JWT
	regexp.MustCompile(`\b(sk|rk)-[A-Za-z0-9]{10,}\b`),                          // OpenAI/Anthropic-style keys
	regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}\b`),                              // GitHub tokens
	regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),                           // AWS access keys
	regexp.MustCompile(`(?i)\bapikey_[A-Za-z0-9]+\b`),
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._-]+\b`),
	regexp.MustCompile(`(?i)\b[A-Z0-9_]*_KEY\s*=\s*\S+`),
}

// redact replaces every secret-pattern match with a fixed marker.
func redact(s string) string {
	for _, re := range secretPatterns {
		s = re.ReplaceAllString(s, "[REDACTED]")
	}
	return s
}

// providerName returns a short label for a base_url, for the audit log.
func providerName(baseURL string) string {
	switch {
	case strings.Contains(baseURL, "openrouter.ai"):
		return "openrouter"
	case strings.Contains(baseURL, "typesafe.ai"):
		return "typesafe"
	case strings.Contains(baseURL, "vercel.sh"):
		return "vercel"
	case baseURL == "":
		return ""
	default:
		return "custom"
	}
}
