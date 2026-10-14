package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to a monitor over its Unix socket. Its Decide method never
// fails open: anything short of a well-formed allow is a deny.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the monitor socket at socketPath. Each
// request is bounded by timeout end to end.
func NewClient(socketPath string, timeout time.Duration) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		DisableKeepAlives: true,
	}
	return &Client{http: &http.Client{Transport: transport, Timeout: timeout}}
}

// Decide asks whether op may proceed in session.
func (c *Client) Decide(ctx context.Context, session string, op Operation) DecideResponse {
	body, _ := json.Marshal(DecideRequest{Version: Version, Session: session, Operation: op})
	status, resp, err := c.Post(ctx, PathDecide, body)
	if err != nil {
		return denyResponse(ReasonMonitorUnavailable)
	}
	return InterpretDecide(status, resp)
}

// Taint durably marks session as tainted. It returns an error unless the
// monitor confirms the taint was recorded.
func (c *Client) Taint(ctx context.Context, session string, source TaintSource) (TaintResponse, error) {
	body, _ := json.Marshal(TaintRequest{Version: Version, Session: session, Source: source})
	status, raw, err := c.Post(ctx, PathTaint, body)
	if err != nil {
		return taintFailure(ReasonMonitorUnavailable), fmt.Errorf("monitor unavailable: %w", err)
	}
	var resp TaintResponse
	if err := strictUnmarshal(raw, &resp); err != nil || resp.Version != Version {
		return taintFailure(ReasonMalformedResponse), fmt.Errorf("malformed taint response (HTTP %d)", status)
	}
	if status != http.StatusOK || !resp.Tainted {
		return resp, fmt.Errorf("taint not recorded (HTTP %d): %s", status, resp.Reason)
	}
	return resp, nil
}

// Post sends body to path and returns the raw status and response body.
// It is exported so fixtures can exercise malformed and unknown requests.
func (c *Client) Post(ctx context.Context, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://monitor"+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, raw, nil
}

// InterpretDecide turns a raw monitor reply into a decision. Only an
// HTTP 200 carrying a well-formed v1 allow is an allow; every other reply
// is a deny, keeping the server's reason when it supplied a valid one.
func InterpretDecide(status int, body []byte) DecideResponse {
	var resp DecideResponse
	if err := strictUnmarshal(body, &resp); err != nil || resp.Version != Version || resp.Reason == "" {
		return denyResponse(ReasonMalformedResponse)
	}
	switch {
	case resp.Decision == Allow && status == http.StatusOK:
		return resp
	case resp.Decision == Deny:
		return resp
	default:
		return denyResponse(ReasonMalformedResponse)
	}
}

func strictUnmarshal(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}
