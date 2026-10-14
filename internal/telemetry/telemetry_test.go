package telemetry

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// collector is a fake OTLP/HTTP logs endpoint. It records each request
// body and answers with the current reply.
type collector struct {
	*httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	reply  func(w http.ResponseWriter)
	got    chan struct{}
}

func newCollector(t *testing.T) *collector {
	t.Helper()
	c := &collector{got: make(chan struct{}, 1024)}
	c.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c.mu.Lock()
		reply := c.reply
		if r.URL.Path == "/v1/logs" && r.Method == http.MethodPost && r.Header.Get("Content-Type") == "application/json" {
			c.bodies = append(c.bodies, body)
		}
		c.mu.Unlock()
		if reply != nil {
			reply(w)
		} else {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{}`)
		}
		select {
		case c.got <- struct{}{}:
		default:
		}
	}))
	t.Cleanup(c.Close)
	return c
}

func (c *collector) setReply(f func(w http.ResponseWriter)) {
	c.mu.Lock()
	c.reply = f
	c.mu.Unlock()
}

func (c *collector) raw() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Join(c.bodies, []byte("\n"))
}

// records decodes every log record the collector accepted.
func (c *collector) records(t *testing.T) []logRecord {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []logRecord
	for _, b := range c.bodies {
		var req exportRequest
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			t.Fatalf("collector got a body that is not the declared shape: %v\n%s", err, b)
		}
		for _, rl := range req.ResourceLogs {
			checkResource(t, rl.Resource.Attributes)
			for _, sl := range rl.ScopeLogs {
				if sl.Scope.Name != ScopeName {
					t.Errorf("scope %q", sl.Scope.Name)
				}
				out = append(out, sl.LogRecords...)
			}
		}
	}
	return out
}

func checkResource(t *testing.T, attrs []attribute) {
	t.Helper()
	want := map[string]string{
		"service.name":                   ServiceName,
		"service.version":                "test-version",
		"barmkin.proto.version":          "1",
		"barmkin.journal.record_version": "1",
		"barmkin.telemetry.schema":       "1",
	}
	if len(attrs) != len(want) {
		t.Errorf("resource attributes %+v", attrs)
	}
	for _, a := range attrs {
		if got := valueOf(a); got != want[a.Key] {
			t.Errorf("resource %s = %q, want %q", a.Key, got, want[a.Key])
		}
	}
}

func valueOf(a attribute) string {
	switch {
	case a.Value.StringValue != nil:
		return *a.Value.StringValue
	case a.Value.IntValue != nil:
		return *a.Value.IntValue
	}
	return ""
}

func attrs(r logRecord) map[string]string {
	m := map[string]string{}
	for _, a := range r.Attributes {
		m[a.Key] = valueOf(a)
	}
	return m
}

func testKey() []byte { return bytes.Repeat([]byte{7}, KeySize) }

func fastConfig(endpoint string) Config {
	return Config{Endpoint: endpoint, Timeout: time.Second, QueueSize: 64, MaxBatch: 16, Interval: 10 * time.Millisecond}
}

func newExporter(t *testing.T, cfg Config) *Exporter {
	t.Helper()
	e, err := New(cfg, testKey(), "test-version", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e
}

// waitFor polls cond until it holds or a few seconds pass.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// The tokens, uids and content a monitor holds that must never be exported.
const (
	secretSession = "session-SECRET-one"
	secretRoot    = "root-SECRET-two"
	secretUID     = 4_123_456_789
)

var lineagePattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// allowed is every attribute an event may carry, with the values it may
// take. A nil set means the value is checked by lineagePattern or is a count.
var allowed = map[string]map[string][]string{
	EventRegister: {"barmkin.event": {EventRegister}, "barmkin.host": hosts, "barmkin.lineage": nil},
	EventRaise: {"barmkin.event": {EventRaise}, "barmkin.host": hosts, "barmkin.lineage": nil,
		"barmkin.leg": {"untrusted", "sensitive"}, "barmkin.source": sources},
	EventStart:    {"barmkin.event": {EventStart}, "barmkin.recovery": {"clean", "unclean", "damaged", "unreadable"}},
	EventShutdown: {"barmkin.event": {EventShutdown}},
	EventDegraded: {"barmkin.event": {EventDegraded}},
	EventLoss:     {"barmkin.event": {EventLoss}, "barmkin.export.dropped": nil, "barmkin.export.failed": nil},
}

var (
	hosts   = []string{string(proto.HostClaudeCode), string(proto.HostOpenCode)}
	sources = []string{"mcp", "fetch", "read", "peer", "skill", "invisible", "credential", "unknown_session", "monitor_restart"}
	counts  = regexp.MustCompile(`^[0-9]+$`)
)

// checkContentFree fails unless every record carries only allowlisted
// attributes with allowlisted values.
func checkContentFree(t *testing.T, records []logRecord) {
	t.Helper()
	for _, r := range records {
		allow, ok := allowed[r.EventName]
		if !ok {
			t.Errorf("unknown event %q", r.EventName)
			continue
		}
		for k, v := range attrs(r) {
			values, ok := allow[k]
			switch {
			case !ok:
				t.Errorf("%s carries unexpected attribute %s=%q", r.EventName, k, v)
			case values != nil && !slices.Contains(values, v):
				t.Errorf("%s: %s=%q is outside its closed set", r.EventName, k, v)
			case values == nil && k == "barmkin.lineage" && !lineagePattern.MatchString(v):
				t.Errorf("%s: lineage %q is not a pseudonym", r.EventName, v)
			case values == nil && k != "barmkin.lineage" && !counts.MatchString(v):
				t.Errorf("%s: %s=%q is not a count", r.EventName, k, v)
			}
		}
		if len(r.Attributes) != len(attrs(r)) {
			t.Errorf("%s repeats an attribute", r.EventName)
		}
	}
}

func TestExportIsContentFree(t *testing.T) {
	col := newCollector(t)
	e := newExporter(t, fastConfig(col.URL+"/v1/logs"))
	at := time.Unix(1_800_000_000, 123)
	e.Started(at, RecoveryUnclean, []journal.Record{
		{Kind: journal.KindRaise, UID: secretUID, Host: proto.HostOpenCode, Root: secretRoot, Leg: journal.LegUntrusted, Source: proto.SourceMonitorRestart},
	})
	e.Journaled(at,
		journal.Record{Kind: journal.KindRegister, UID: secretUID, Host: proto.HostClaudeCode, Session: secretSession, Root: secretRoot},
		journal.Record{Kind: journal.KindRaise, UID: secretUID, Host: proto.HostClaudeCode, Root: secretRoot, Leg: journal.LegSensitive, Source: proto.SourceCredential},
		journal.Record{Kind: journal.KindStart},
		journal.Record{Kind: journal.KindShutdown},
	)
	e.Degraded(at)
	e.Close()

	records := col.records(t)
	var names []string
	for _, r := range records {
		names = append(names, r.EventName)
	}
	want := []string{EventRaise, EventStart, EventRegister, EventRaise, EventShutdown, EventDegraded}
	if !slices.Equal(names, want) {
		t.Fatalf("events %v, want %v", names, want)
	}
	checkContentFree(t, records)

	raw := string(col.raw())
	for _, secret := range []string{secretSession, secretRoot, "4123456789", "SECRET"} {
		if strings.Contains(raw, secret) {
			t.Errorf("export carries %q:\n%s", secret, raw)
		}
	}
	for _, r := range records {
		if r.TimeUnixNano != "1800000000000000123" {
			t.Errorf("%s time %s", r.EventName, r.TimeUnixNano)
		}
	}
	// The register and the raise of one lineage share its pseudonym; the
	// same root under another host is another lineage.
	reg, raise, restart := attrs(records[2]), attrs(records[3]), attrs(records[0])
	if reg["barmkin.lineage"] != raise["barmkin.lineage"] {
		t.Errorf("one lineage, two pseudonyms: %q %q", reg["barmkin.lineage"], raise["barmkin.lineage"])
	}
	if restart["barmkin.lineage"] == reg["barmkin.lineage"] {
		t.Error("lineages on two hosts share a pseudonym")
	}
	if a := attrs(records[1]); a["barmkin.recovery"] != "unclean" || records[1].SeverityNumber != severityWarn {
		t.Errorf("start record %+v", records[1])
	}
}

func TestLineagePseudonym(t *testing.T) {
	key := testKey()
	id := lineageID(key, 1000, proto.HostClaudeCode, "r")
	if !lineagePattern.MatchString(id) {
		t.Fatalf("pseudonym %q", id)
	}
	if lineageID(key, 1000, proto.HostClaudeCode, "r") != id {
		t.Error("pseudonym is not stable")
	}
	other := bytes.Repeat([]byte{8}, KeySize)
	for name, got := range map[string]string{
		"uid":  lineageID(key, 1001, proto.HostClaudeCode, "r"),
		"host": lineageID(key, 1000, proto.HostOpenCode, "r"),
		"root": lineageID(key, 1000, proto.HostClaudeCode, "r2"),
		"key":  lineageID(other, 1000, proto.HostClaudeCode, "r"),
	} {
		if got == id {
			t.Errorf("another %s gives the same pseudonym", name)
		}
	}
}

func TestCollectorFailuresAreCountedAndReported(t *testing.T) {
	col := newCollector(t)
	cfg := fastConfig(col.URL + "/v1/logs")
	cfg.Timeout = 200 * time.Millisecond
	e := newExporter(t, cfg)
	shutdown := journal.Record{Kind: journal.KindShutdown}

	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	cases := []struct {
		code  string
		reply func(w http.ResponseWriter)
	}{
		{FailStatus, func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{FailStatus, func(w http.ResponseWriter) {
			w.Header().Set("Location", "/v1/logs-elsewhere")
			w.WriteHeader(http.StatusTemporaryRedirect)
		}},
		{FailMalformed, func(w http.ResponseWriter) { io.WriteString(w, `{"partialSuccess":`) }},
		{FailMalformed, func(w http.ResponseWriter) { io.WriteString(w, strings.Repeat(" ", maxResponseBytes+1)+"{}") }},
		{FailRejected, func(w http.ResponseWriter) {
			io.WriteString(w, `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"nope"}}`)
		}},
		{FailTimeout, func(w http.ResponseWriter) {
			select {
			case <-block:
			case <-time.After(5 * time.Second):
			}
		}},
	}
	failed := uint64(0)
	for _, tc := range cases {
		col.setReply(tc.reply)
		e.Journaled(time.Now(), shutdown)
		failed++
		waitFor(t, tc.code, func() bool { return e.Stats().Failed == failed })
		if got := e.Stats().LastFailure; got != tc.code {
			t.Errorf("failure %q, want %q", got, tc.code)
		}
	}
	if s := e.Stats(); s.Sent != 0 {
		t.Errorf("sent %d while the collector failed", s.Sent)
	}

	// The collector recovers: the next batch carries one loss record with
	// everything lost so far, and later batches carry none.
	col.mu.Lock()
	col.bodies = nil
	col.mu.Unlock()
	col.setReply(nil)
	e.Journaled(time.Now(), shutdown)
	waitFor(t, "a delivered batch", func() bool { return e.Stats().Sent == 1 })
	e.Journaled(time.Now(), shutdown)
	waitFor(t, "a second batch", func() bool { return e.Stats().Sent == 2 })
	e.Close()

	var losses []map[string]string
	for _, r := range col.records(t) {
		if r.EventName == EventLoss {
			losses = append(losses, attrs(r))
		}
	}
	if len(losses) != 1 || losses[0]["barmkin.export.failed"] != "6" || losses[0]["barmkin.export.dropped"] != "0" {
		t.Errorf("loss records %v, want one reporting 6 failed", losses)
	}
	checkContentFree(t, col.records(t))
}

func TestUnreachableCollector(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	e := newExporter(t, fastConfig("http://"+addr+"/v1/logs"))
	e.Journaled(time.Now(), journal.Record{Kind: journal.KindShutdown})
	waitFor(t, "a failed batch", func() bool { return e.Stats().Failed == 1 })
	if got := e.Stats().LastFailure; got != FailTransport {
		t.Errorf("failure %q, want transport", got)
	}
}

// TestHandOffNeverBlocks holds the collector so that no request ever
// returns: the queue fills, every later event is dropped and counted, no
// hand-off waits, and Close returns within the request timeout.
func TestHandOffNeverBlocks(t *testing.T) {
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hang.Close()
	defer close(release)

	cfg := Config{Endpoint: hang.URL + "/v1/logs", Timeout: 300 * time.Millisecond, QueueSize: 4, MaxBatch: 1, Interval: 10 * time.Millisecond}
	e, err := New(cfg, testKey(), "test-version", t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	rec := journal.Record{Kind: journal.KindRaise, UID: 1, Host: proto.HostClaudeCode, Root: "r", Leg: journal.LegUntrusted, Source: proto.SourceMCP}
	const n = 10_000
	var slowest time.Duration
	start := time.Now()
	for range n {
		t0 := time.Now()
		e.Journaled(t0, rec)
		slowest = max(slowest, time.Since(t0))
	}
	if total := time.Since(start); total > cfg.Timeout {
		t.Errorf("%d hand-offs took %s, longer than one request timeout", n, total)
	}
	if slowest > 50*time.Millisecond {
		t.Errorf("slowest hand-off took %s", slowest)
	}
	if s := e.Stats(); s.Dropped < n-uint64(cfg.QueueSize)-2 {
		t.Errorf("dropped %d of %d with a queue of %d", s.Dropped, n, cfg.QueueSize)
	}
	if got := len(e.queue); got > cfg.QueueSize {
		t.Errorf("queue holds %d, over its bound %d", got, cfg.QueueSize)
	}

	t0 := time.Now()
	e.Close()
	if took := time.Since(t0); took > 2*cfg.Timeout+200*time.Millisecond {
		t.Errorf("Close took %s with a hung collector", took)
	}
	e.Journaled(time.Now(), rec) // after Close: dropped, never a panic
	s := e.Stats()
	if s.Sent != 0 || s.Dropped+s.Failed != n+1 {
		t.Errorf("stats %+v: every event must be sent, dropped or failed", s)
	}
}

func TestNilExporterIsOff(t *testing.T) {
	var e *Exporter
	e.Journaled(time.Now(), journal.Record{Kind: journal.KindShutdown})
	e.Started(time.Now(), RecoveryClean, nil)
	e.Degraded(time.Now())
	e.Close()
	if e.Stats() != (Stats{}) {
		t.Error("a nil exporter counted something")
	}
}

func TestParseConfig(t *testing.T) {
	cfg, err := parseConfig([]byte(`{"endpoint":"http://127.0.0.1:4318/v1/logs"}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != DefaultTimeout || cfg.QueueSize != DefaultQueueSize || cfg.MaxBatch != DefaultMaxBatch || cfg.Interval != DefaultInterval {
		t.Errorf("defaults %+v", cfg)
	}
	cfg, err = parseConfig([]byte(`{"endpoint":"https://otel.example:4318/v1/logs","timeout_ms":500,"queue_size":10,"max_batch":5,"flush_interval_ms":250}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != 500*time.Millisecond || cfg.QueueSize != 10 || cfg.MaxBatch != 5 || cfg.Interval != 250*time.Millisecond {
		t.Errorf("parsed %+v", cfg)
	}

	for name, body := range map[string]string{
		"empty":              `{}`,
		"not JSON":           `endpoint: x`,
		"unknown field":      `{"endpoint":"http://c/v1/logs","headers":{"x-collector":"y"}}`,
		"trailing data":      `{"endpoint":"http://c/v1/logs"} {}`,
		"ftp":                `{"endpoint":"ftp://c/v1/logs"}`,
		"relative":           `{"endpoint":"/v1/logs"}`,
		"no host":            `{"endpoint":"http:///v1/logs"}`,
		"user info":          `{"endpoint":"http://collector-user@c/v1/logs"}`,
		"query":              `{"endpoint":"http://c/v1/logs?token=x"}`,
		"fragment":           `{"endpoint":"http://c/v1/logs#x"}`,
		"negative":           `{"endpoint":"http://c/v1/logs","queue_size":-1}`,
		"timeout too long":   `{"endpoint":"http://c/v1/logs","timeout_ms":60000}`,
		"queue too large":    `{"endpoint":"http://c/v1/logs","queue_size":1000000}`,
		"batch too large":    `{"endpoint":"http://c/v1/logs","max_batch":5000}`,
		"interval too short": `{"endpoint":"http://c/v1/logs","flush_interval_ms":1}`,
	} {
		if _, err := parseConfig([]byte(body)); err == nil {
			t.Errorf("%s: accepted %s", name, body)
		}
	}
}

// asRoot makes this test's uid stand in for root as the configuration's
// required owner.
func asRoot(t *testing.T) {
	rootUID = os.Getuid()
	t.Cleanup(func() { rootUID = 0 })
}

func writeConfig(t *testing.T, dir string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, "telemetry.json")
	if err := os.WriteFile(path, []byte(`{"endpoint":"http://127.0.0.1:4318/v1/logs"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadConfigRequiresRoot(t *testing.T) {
	asRoot(t)
	dir := t.TempDir()
	path := writeConfig(t, dir, 0o644)
	if _, err := LoadConfig(path); err != nil {
		t.Fatalf("root's 0644 config: %v", err)
	}

	cases := map[string]func(t *testing.T) string{
		"relative path": func(t *testing.T) string { return "telemetry.json" },
		"missing":       func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
		"group-writable": func(t *testing.T) string {
			return writeConfig(t, t.TempDir(), 0o664)
		},
		"world-writable": func(t *testing.T) string {
			return writeConfig(t, t.TempDir(), 0o646)
		},
		"not root's": func(t *testing.T) string {
			p := writeConfig(t, t.TempDir(), 0o644)
			rootUID = os.Getuid() + 1
			return p
		},
		"symlink": func(t *testing.T) string {
			d := t.TempDir()
			real := writeConfig(t, d, 0o644)
			link := filepath.Join(d, "link.json")
			os.Symlink(real, link)
			return link
		},
		"directory": func(t *testing.T) string {
			d := filepath.Join(t.TempDir(), "conf")
			os.Mkdir(d, 0o755)
			return d
		},
		"group-writable directory": func(t *testing.T) string {
			d := t.TempDir()
			p := writeConfig(t, d, 0o644)
			os.Chmod(d, 0o775)
			return p
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			asRoot(t)
			if _, err := LoadConfig(setup(t)); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestLoadKey(t *testing.T) {
	dir := t.TempDir()
	key, err := LoadKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != KeySize {
		t.Fatalf("key of %d bytes", len(key))
	}
	fi, err := os.Stat(filepath.Join(dir, keyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", fi, err)
	}
	again, err := LoadKey(dir)
	if err != nil || !bytes.Equal(again, key) {
		t.Errorf("key changed across loads: %v", err)
	}
	if other, _ := LoadKey(t.TempDir()); bytes.Equal(other, key) {
		t.Error("two state directories share a key")
	}

	cases := map[string]func(dir string){
		"readable by group": func(dir string) { os.WriteFile(filepath.Join(dir, keyFile), key, 0o640) },
		"short":             func(dir string) { os.WriteFile(filepath.Join(dir, keyFile), key[:8], 0o600) },
		"long":              func(dir string) { os.WriteFile(filepath.Join(dir, keyFile), append(key, 0), 0o600) },
		"symlink": func(dir string) {
			real := filepath.Join(dir, "real")
			os.WriteFile(real, key, 0o600)
			os.Symlink(real, filepath.Join(dir, keyFile))
		},
		"directory": func(dir string) { os.Mkdir(filepath.Join(dir, keyFile), 0o700) },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			setup(dir)
			if _, err := LoadKey(dir); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestNewChecksItsInputs(t *testing.T) {
	if _, err := New(Config{}, testKey(), "v", nil); err == nil {
		t.Error("accepted a config without an endpoint")
	}
	if _, err := New(fastConfig("http://127.0.0.1:1/v1/logs"), []byte("short"), "v", nil); err == nil {
		t.Error("accepted a short key")
	}
}
