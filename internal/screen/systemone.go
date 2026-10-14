package screen

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Jev's "System One" protocol, ported from barmkin-mod's
// hooks/lib/system-one-client.ts: POST {endpoint}/v1/systemone with
// {model, state, questions}. Every access path serves the same shape. The
// client only answers noul (probability-of-yes) questions; composing them
// into a decision is compose.go's job, and it only ever tightens.

// SystemOnePath is the operation's path under the endpoint.
const SystemOnePath = "/v1/systemone"

// ModelPattern is the model spelling an answer must carry.
var ModelPattern = regexp.MustCompile(`jev-1\.13\b`)

// maxResponseBytes bounds a System One response body. An answer to four
// questions is a few hundred bytes.
const maxResponseBytes = 64 << 10

// noulQuestion is one question on the wire.
type noulQuestion struct {
	Type         string `json:"type"`
	Instructions string `json:"instructions"`
}

// systemOneRequest is the request body. The screened window travels as
// state.content; the instructions come only from a QuestionSet.
type systemOneRequest struct {
	Model     string                  `json:"model"`
	State     map[string]string       `json:"state"`
	Questions map[string]noulQuestion `json:"questions"`
}

func buildRequest(model, window string, qs *QuestionSet) systemOneRequest {
	questions := make(map[string]noulQuestion, len(qs.IDs))
	for _, id := range qs.IDs {
		questions[id] = noulQuestion{Type: "noul", Instructions: qs.Instructions[id]}
	}
	return systemOneRequest{Model: model, State: map[string]string{"content": window}, Questions: questions}
}

// Failure names why a window got no answer. It is a closed set: an endpoint's
// text never reaches a caller.
type Failure string

const (
	FailureNone      Failure = ""
	FailureTimeout   Failure = "timeout"   // no answer within the call's deadline
	FailureNetwork   Failure = "network"   // the request could not be made or read
	FailureHTTP      Failure = "http"      // a status other than 2xx
	FailureMalformed Failure = "malformed" // a 2xx body that is not a valid answer
)

// Answer is one window's result: the noul probabilities for each question
// asked, or the failure that left it unanswered.
type Answer struct {
	Model   string
	Answers map[string]float64
	Failure Failure
	Status  int // the HTTP status, for FailureHTTP
}

// OK reports whether the window was answered.
func (a Answer) OK() bool { return a.Failure == FailureNone }

// transient reports whether a failure is worth one more try: the endpoint
// was slow, unreachable, rate limited or erroring. A malformed or refused
// answer would fail the same way again.
func (a Answer) transient() bool {
	switch a.Failure {
	case FailureTimeout, FailureNetwork:
		return true
	case FailureHTTP:
		return a.Status == http.StatusTooManyRequests || (a.Status >= 500 && a.Status <= 599)
	}
	return false
}

func malformed() Answer { return Answer{Failure: FailureMalformed} }

// parseResponse strictly validates a System One response body: a 2xx body
// is not yet an answer. Any deviation is a failure, never a best-effort
// partial result, so a malformed or adversarial response degrades to
// unanswered rather than being half-trusted.
func parseResponse(body []byte, questionIDs []string) Answer {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return malformed()
	}
	var model string
	if err := json.Unmarshal(raw["model"], &model); err != nil || !ModelPattern.MatchString(model) {
		return malformed()
	}
	var answers map[string]json.RawMessage
	if err := json.Unmarshal(raw["answers"], &answers); err != nil || answers == nil || len(answers) != len(questionIDs) {
		return malformed()
	}
	out := make(map[string]float64, len(questionIDs))
	for _, id := range questionIDs {
		// A map, not a struct: encoding/json matches struct fields without
		// regard to case, and the keys must match exactly.
		var ans map[string]json.RawMessage
		var typ string
		data, ok := answers[id]
		if !ok || json.Unmarshal(data, &ans) != nil || json.Unmarshal(ans["type"], &typ) != nil || typ != "noul" {
			return malformed()
		}
		p, ok := parseNoul(ans["noul"])
		if !ok {
			return malformed()
		}
		out[id] = p
	}
	return Answer{Model: model, Answers: out}
}

// parseNoul accepts a JSON number in [0, 1] and nothing else.
func parseNoul(data json.RawMessage) (float64, bool) {
	s := strings.TrimSpace(string(data))
	if s == "" || !(s[0] == '-' || (s[0] >= '0' && s[0] <= '9')) {
		return 0, false
	}
	p, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(p) || p < 0 || p > 1 {
		return 0, false
	}
	return p, true
}

// systemOneClient makes System One calls to one endpoint. Each call is
// bounded by timeout and never follows a redirect, so the credential is
// only ever sent to the configured endpoint.
type systemOneClient struct {
	url        string
	model      string
	credential Credential
	timeout    time.Duration
	http       *http.Client
}

// ask sends one window with one question set. It never returns an error:
// every failure is an unanswered Answer, which the screen treats as
// "classifier unavailable" for that window, never as a pass.
func (c *systemOneClient) ask(ctx context.Context, window string, qs *QuestionSet) Answer {
	body, err := json.Marshal(buildRequest(c.model, window, qs))
	if err != nil {
		return Answer{Failure: FailureNetwork}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return Answer{Failure: FailureNetwork}
	}
	req.Header.Set("Content-Type", "application/json")
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+string(c.credential))
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return transportFailure(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Answer{Failure: FailureHTTP, Status: resp.StatusCode}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return transportFailure(ctx, err)
	}
	if len(data) > maxResponseBytes {
		return malformed()
	}
	return parseResponse(data, qs.IDs)
}

func transportFailure(ctx context.Context, err error) Answer {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Answer{Failure: FailureTimeout}
	}
	return Answer{Failure: FailureNetwork}
}

// noRedirect refuses every redirect: a 3xx is a failed call.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
