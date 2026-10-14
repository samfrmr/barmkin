package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// callKey identifies one registered tool call.
type callKey struct{ session, call string }

// SetPresenceTTL changes how long new registrations stay live.
func (s *Server) SetPresenceTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.presenceTTL = d
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if status, reason := decodeRequest(w, r, &req, "version", "session", "call"); reason != "" {
		writeJSON(w, status, registerFailure(reason))
		return
	}
	if reason := checkCall(req.Version, req.Session, req.Call); reason != "" {
		writeJSON(w, http.StatusBadRequest, registerFailure(reason))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if len(s.presence) >= MaxPresence {
		for k, expiry := range s.presence {
			if !now.Before(expiry) {
				delete(s.presence, k)
			}
		}
	}
	if len(s.presence) >= MaxPresence {
		writeJSON(w, http.StatusServiceUnavailable, registerFailure(ReasonCapacityExceeded))
		return
	}
	s.presence[callKey{req.Session, req.Call}] = now.Add(s.presenceTTL)
	writeJSON(w, http.StatusOK, RegisterResponse{Version: Version, Registered: true, Reason: ReasonOK})
}

func (s *Server) handlePresence(w http.ResponseWriter, r *http.Request) {
	var req PresenceRequest
	if status, reason := decodeRequest(w, r, &req, "version", "session", "call"); reason != "" {
		writeJSON(w, status, denyResponse(reason))
		return
	}
	if reason := checkCall(req.Version, req.Session, req.Call); reason != "" {
		writeJSON(w, http.StatusBadRequest, denyResponse(reason))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	key := callKey{req.Session, req.Call}
	expiry, registered := s.presence[key]
	switch {
	case s.degraded:
		writeJSON(w, http.StatusServiceUnavailable, denyResponse(ReasonJournalFailure))
	case !registered:
		writeJSON(w, http.StatusOK, denyResponse(ReasonUnregistered))
	case !s.now().Before(expiry):
		delete(s.presence, key)
		writeJSON(w, http.StatusOK, denyResponse(ReasonExpired))
	default:
		// Consume the registration: it admits this one call only.
		delete(s.presence, key)
		writeJSON(w, http.StatusOK, DecideResponse{Version: Version, Decision: Allow, Reason: ReasonOK})
	}
}

// checkCall validates the fields shared by register and presence requests.
func checkCall(version int, session, call string) Reason {
	switch {
	case version != Version:
		return ReasonUnsupportedVersion
	case !ValidSession(session), !ValidCall(call):
		return ReasonMalformedRequest
	}
	return ""
}

func registerFailure(reason Reason) RegisterResponse {
	return RegisterResponse{Version: Version, Registered: false, Reason: reason}
}

// Register records that a shim saw call in session. It returns an error
// unless the monitor confirms the call is live.
func (c *Client) Register(ctx context.Context, session, call string) (RegisterResponse, error) {
	body, _ := json.Marshal(RegisterRequest{Version: Version, Session: session, Call: call})
	status, raw, err := c.Post(ctx, PathRegister, body)
	if err != nil {
		return registerFailure(ReasonMonitorUnavailable), fmt.Errorf("monitor unavailable: %w", err)
	}
	var resp RegisterResponse
	if err := strictUnmarshal(raw, &resp); err != nil || resp.Version != Version {
		return registerFailure(ReasonMalformedResponse), fmt.Errorf("malformed register response (HTTP %d)", status)
	}
	if status != http.StatusOK || !resp.Registered {
		return resp, fmt.Errorf("call not registered (HTTP %d): %s", status, resp.Reason)
	}
	return resp, nil
}

// Presence asks whether call in session has a live registration. Like
// Decide, it never fails open, and an allow consumes the registration.
func (c *Client) Presence(ctx context.Context, session, call string) DecideResponse {
	body, _ := json.Marshal(PresenceRequest{Version: Version, Session: session, Call: call})
	status, resp, err := c.Post(ctx, PathPresence, body)
	if err != nil {
		return denyResponse(ReasonMonitorUnavailable)
	}
	return InterpretDecide(status, resp)
}
