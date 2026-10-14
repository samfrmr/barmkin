package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Server answers v1 requests from in-memory taint state backed by a Journal,
// and from in-memory shim registrations that are never journaled.
type Server struct {
	mu       sync.Mutex
	journal  *Journal
	tainted  map[string]bool
	degraded bool // a taint could not be journaled; deny everything

	presence    map[callKey]time.Time // live registrations and their expiry
	presenceTTL time.Duration
	now         func() time.Time
}

// NewServer builds a server from an open journal and its replayed records.
func NewServer(j *Journal, records []Record) *Server {
	s := &Server{
		journal:     j,
		tainted:     map[string]bool{},
		presence:    map[callKey]time.Time{},
		presenceTTL: PresenceTTL,
		now:         time.Now,
	}
	for _, r := range records {
		s.tainted[r.Session] = true
	}
	return s
}

// ServeHTTP routes exact v1 paths. Everything else is denied.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case PathDecide:
		s.handleDecide(w, r)
	case PathTaint:
		s.handleTaint(w, r)
	case PathRegister:
		s.handleRegister(w, r)
	case PathPresence:
		s.handlePresence(w, r)
	default:
		writeJSON(w, http.StatusNotFound, denyResponse(ReasonUnknownEndpoint))
	}
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var req DecideRequest
	if status, reason := decodeRequest(w, r, &req, "version", "session", "operation"); reason != "" {
		writeJSON(w, status, denyResponse(reason))
		return
	}
	switch {
	case req.Version != Version:
		writeJSON(w, http.StatusBadRequest, denyResponse(ReasonUnsupportedVersion))
		return
	case !ValidSession(req.Session):
		writeJSON(w, http.StatusBadRequest, denyResponse(ReasonMalformedRequest))
		return
	case !req.Operation.known():
		writeJSON(w, http.StatusBadRequest, denyResponse(ReasonUnknownOperation))
		return
	}

	s.mu.Lock()
	degraded, tainted := s.degraded, s.tainted[req.Session]
	s.mu.Unlock()

	switch {
	case degraded:
		writeJSON(w, http.StatusServiceUnavailable, denyResponse(ReasonJournalFailure))
	case tainted && req.Operation == OpProtected:
		writeJSON(w, http.StatusOK, denyResponse(ReasonTainted))
	default:
		writeJSON(w, http.StatusOK, DecideResponse{Version: Version, Decision: Allow, Reason: ReasonOK})
	}
}

func (s *Server) handleTaint(w http.ResponseWriter, r *http.Request) {
	var req TaintRequest
	if status, reason := decodeRequest(w, r, &req, "version", "session", "source"); reason != "" {
		writeJSON(w, status, taintFailure(reason))
		return
	}
	switch {
	case req.Version != Version:
		writeJSON(w, http.StatusBadRequest, taintFailure(ReasonUnsupportedVersion))
		return
	case !ValidSession(req.Session):
		writeJSON(w, http.StatusBadRequest, taintFailure(ReasonMalformedRequest))
		return
	case !req.Source.known():
		writeJSON(w, http.StatusBadRequest, taintFailure(ReasonUnknownSource))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tainted[req.Session] {
		writeJSON(w, http.StatusOK, TaintResponse{Version: Version, Tainted: true, Reason: ReasonOK})
		return
	}
	// Taint in memory before journaling so a failed append still denies.
	s.tainted[req.Session] = true
	if err := s.journal.AppendTaint(req.Session, req.Source); err != nil {
		s.degraded = true
		writeJSON(w, http.StatusServiceUnavailable, taintFailure(ReasonJournalFailure))
		return
	}
	writeJSON(w, http.StatusOK, TaintResponse{Version: Version, Tainted: true, Reason: ReasonOK})
}

// decodeRequest strictly decodes a POST body into v. The body must be a
// single JSON object whose keys are exactly drawn from fields (matched
// case-sensitively, no duplicates). It returns a non-empty reason on failure.
func decodeRequest(w http.ResponseWriter, r *http.Request, v any, fields ...string) (int, Reason) {
	if r.Method != http.MethodPost {
		return http.StatusMethodNotAllowed, ReasonMalformedRequest
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		return http.StatusBadRequest, ReasonMalformedRequest
	}
	if err := checkKeys(body, fields); err != nil {
		return http.StatusBadRequest, ReasonMalformedRequest
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return http.StatusBadRequest, ReasonMalformedRequest
	}
	return http.StatusOK, ""
}

// checkKeys verifies body is exactly one JSON object with no unknown or
// repeated keys. encoding/json alone matches keys case-insensitively and
// keeps the last duplicate, both of which would let odd requests through.
func checkKeys(body []byte, fields []string) error {
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return errors.New("not an object")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if !allowed[key] || seen[key] {
			return fmt.Errorf("unexpected key %q", key)
		}
		seen[key] = true
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func denyResponse(reason Reason) DecideResponse {
	return DecideResponse{Version: Version, Decision: Deny, Reason: reason}
}

func taintFailure(reason Reason) TaintResponse {
	return TaintResponse{Version: Version, Tainted: false, Reason: reason}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// Listen opens the Unix socket at path with owner-only permissions,
// replacing a stale socket left by a previous process. Callers should hold
// the journal lock first so a live monitor's socket is never replaced.
func Listen(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("socket dir: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// NewHTTPServer wraps s with conservative timeouts.
func NewHTTPServer(s *Server) *http.Server {
	return &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}
