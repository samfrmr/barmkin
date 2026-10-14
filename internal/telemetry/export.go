package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
)

// SchemaVersion is the version of the exported records' shape.
const SchemaVersion = 1

// ScopeName is the instrumentation scope of every exported record.
const ScopeName = "barmkin.monitor.journal"

// ServiceName is the exported service.name.
const ServiceName = "barmkin-monitor"

// Event codes, the closed set of exported event names.
const (
	EventStart    = "barmkin.monitor.start"
	EventShutdown = "barmkin.monitor.shutdown"
	EventDegraded = "barmkin.monitor.degraded"
	EventRegister = "barmkin.session.register"
	EventRaise    = "barmkin.lineage.raise"
	EventLoss     = "barmkin.export.loss"
)

// Recovery says how the monitor's last run ended, as replay found it.
type Recovery string

const (
	RecoveryClean      Recovery = "clean"      // the journal ended in a clean stop
	RecoveryUnclean    Recovery = "unclean"    // a crash, a kill or a torn tail
	RecoveryDamaged    Recovery = "damaged"    // a damaged journal was moved aside
	RecoveryUnreadable Recovery = "unreadable" // an unreadable journal was moved aside
)

// Failure codes, the closed set of reasons a batch was not delivered.
const (
	FailTimeout   = "timeout"
	FailTransport = "transport"
	FailStatus    = "http_status"
	FailMalformed = "malformed_response"
	FailRejected  = "rejected"
)

// maxResponseBytes bounds the collector response the exporter reads.
const maxResponseBytes = 64 << 10

// event is one queued state change. Only the worker turns root into a
// pseudonym; nothing here is ever exported as is.
type event struct {
	at       time.Time
	name     string
	uid      uint32
	host     proto.Host
	root     string
	leg      journal.Leg
	source   proto.Source
	recovery Recovery
}

// Stats counts what the exporter did with the events it was given.
type Stats struct {
	Sent        uint64 // events a collector accepted
	Dropped     uint64 // events dropped because the queue was full or the exporter closed
	Failed      uint64 // events lost with a batch the collector did not accept
	LastFailure string // the failure code of the last batch that failed
}

// Exporter exports journal events to an OTLP/HTTP collector. A nil
// *Exporter is valid and exports nothing, so export is off by default.
type Exporter struct {
	cfg      Config
	key      []byte
	resource []attribute
	client   *http.Client
	logf     func(format string, args ...any)

	queue  chan event
	stop   chan struct{}
	done   chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool

	sent, dropped, failed atomic.Uint64

	mu          sync.Mutex
	lastFailure string

	// Worker-only state: the loss already reported to a collector.
	reportedDropped, reportedFailed uint64
	failing                         bool
}

// New starts an exporter. version is the monitor's service.version; logf
// receives a line when the export starts or stops failing. The caller must
// Close it.
func New(cfg Config, key []byte, version string, logf func(format string, args ...any)) (*Exporter, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	if len(key) != KeySize {
		return nil, errors.New("telemetry key must be 32 bytes")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if version == "" {
		version = "unknown"
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &Exporter{
		cfg: cfg,
		key: append([]byte(nil), key...),
		resource: []attribute{
			strAttr("service.name", ServiceName),
			strAttr("service.version", version),
			intAttr("barmkin.proto.version", proto.Version),
			intAttr("barmkin.journal.record_version", journal.RecordVersion),
			intAttr("barmkin.telemetry.schema", SchemaVersion),
		},
		client: &http.Client{
			Timeout: cfg.Timeout,
			// A redirect is a failure: the export goes to the configured
			// collector or nowhere.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport: &http.Transport{
				Proxy:                  nil, // never an environment proxy
				DialContext:            (&net.Dialer{Timeout: cfg.Timeout}).DialContext,
				TLSHandshakeTimeout:    cfg.Timeout,
				ResponseHeaderTimeout:  cfg.Timeout,
				MaxIdleConns:           1,
				MaxIdleConnsPerHost:    1,
				IdleConnTimeout:        30 * time.Second,
				MaxResponseHeaderBytes: 16 << 10,
			},
		},
		logf:   logf,
		queue:  make(chan event, cfg.QueueSize),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
		ctx:    ctx,
		cancel: cancel,
	}
	go e.run()
	return e, nil
}

// enqueue hands ev to the worker without ever blocking: when the queue is
// full, or the exporter is closed, ev is dropped and counted.
func (e *Exporter) enqueue(ev event) {
	if e.closed.Load() {
		e.dropped.Add(1)
		return
	}
	select {
	case e.queue <- ev:
	default:
		e.dropped.Add(1)
	}
}

// Journaled exports records the journal has just made durable, at time at.
// The caller must call it only after the append that wrote them returned
// successfully. It never blocks.
func (e *Exporter) Journaled(at time.Time, records ...journal.Record) {
	if e == nil {
		return
	}
	for _, r := range records {
		ev := event{at: at}
		switch r.Kind {
		case journal.KindRegister:
			ev.name, ev.uid, ev.host, ev.root = EventRegister, r.UID, r.Host, r.Root
		case journal.KindRaise:
			ev.name, ev.uid, ev.host, ev.root, ev.leg, ev.source = EventRaise, r.UID, r.Host, r.Root, r.Leg, r.Source
		case journal.KindShutdown:
			ev.name = EventShutdown
		default:
			// A start is exported by Started, with how the last run ended.
			continue
		}
		e.enqueue(ev)
	}
}

// Started exports the monitor's start, after the compacted journal holding
// it is durable: first the raises replay added (monitor_restart after an
// unclean stop), then the start itself with how the last run ended.
func (e *Exporter) Started(at time.Time, recovery Recovery, raises []journal.Record) {
	if e == nil {
		return
	}
	e.Journaled(at, raises...)
	e.enqueue(event{at: at, name: EventStart, recovery: recovery})
}

// Degraded exports that a change could not be journaled.
func (e *Exporter) Degraded(at time.Time) {
	if e == nil {
		return
	}
	e.enqueue(event{at: at, name: EventDegraded})
}

// Stats returns the exporter's counts so far.
func (e *Exporter) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return Stats{Sent: e.sent.Load(), Dropped: e.dropped.Load(), Failed: e.failed.Load(), LastFailure: e.lastFailure}
}

// Close stops the exporter. It sends what is queued in one last attempt
// bounded by the request timeout, abandons anything still in flight after
// that, and returns.
func (e *Exporter) Close() {
	if e == nil || !e.closed.CompareAndSwap(false, true) {
		return
	}
	close(e.stop)
	t := time.NewTimer(e.cfg.Timeout)
	defer t.Stop()
	select {
	case <-e.done:
	case <-t.C:
		e.cancel()
		<-e.done
	}
	e.cancel()
	e.client.CloseIdleConnections()
}

// run is the worker: it batches the queue and sends each batch.
func (e *Exporter) run() {
	defer close(e.done)
	tick := time.NewTicker(e.cfg.Interval)
	defer tick.Stop()
	batch := make([]event, 0, e.cfg.MaxBatch)
	for {
		select {
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= e.cfg.MaxBatch {
				e.send(batch)
				batch = batch[:0]
			}
		case <-tick.C:
			if len(batch) > 0 || e.lossPending() {
				e.send(batch)
				batch = batch[:0]
			}
		case <-e.stop:
			e.drain(batch)
			return
		}
	}
}

// drain sends batch and everything still queued. Close bounds how long it
// may take by cancelling the requests in flight.
func (e *Exporter) drain(batch []event) {
	for {
		select {
		case ev := <-e.queue:
			batch = append(batch, ev)
			if len(batch) >= e.cfg.MaxBatch {
				e.send(batch)
				batch = batch[:0]
			}
		default:
			if len(batch) > 0 || e.lossPending() {
				e.send(batch)
			}
			return
		}
	}
}

func (e *Exporter) lossPending() bool {
	return e.dropped.Load() != e.reportedDropped || e.failed.Load() != e.reportedFailed
}

// send posts one batch, with a loss record when there is loss to report,
// and counts the outcome.
func (e *Exporter) send(batch []event) {
	dropped, failed := e.dropped.Load(), e.failed.Load()
	loss := dropped != e.reportedDropped || failed != e.reportedFailed
	body, err := json.Marshal(e.payload(batch, loss, dropped-e.reportedDropped, failed-e.reportedFailed))
	if err != nil {
		e.fail(len(batch), FailTransport)
		return
	}
	if code := e.post(body); code != "" {
		e.fail(len(batch), code)
		return
	}
	e.sent.Add(uint64(len(batch)))
	if loss {
		e.reportedDropped, e.reportedFailed = dropped, failed
	}
	if e.failing {
		e.failing = false
		e.logf("telemetry export recovered")
	}
}

func (e *Exporter) fail(n int, code string) {
	e.failed.Add(uint64(n))
	e.mu.Lock()
	e.lastFailure = code
	e.mu.Unlock()
	if !e.failing {
		e.failing = true
		e.logf("telemetry export failing (%s); the local journal is unaffected", code)
	}
}

// post sends body and returns a failure code, or "" when the collector
// accepted every record in it.
func (e *Exporter) post(body []byte) string {
	ctx, cancel := context.WithTimeout(e.ctx, e.cfg.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return FailTransport
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return FailTimeout
		}
		return FailTransport
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil || isTimeout(err) {
			return FailTimeout
		}
		return FailTransport
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return FailStatus
	}
	rejected, ok := parseResponse(data)
	switch {
	case !ok:
		return FailMalformed
	case rejected > 0:
		return FailRejected
	}
	return ""
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// parseResponse reads an ExportLogsServiceResponse. An empty body is a full
// success. It reports how many records the collector rejected, and false
// when the response is not one.
func parseResponse(data []byte) (rejected int64, ok bool) {
	if len(data) > maxResponseBytes {
		return 0, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return 0, true
	}
	var resp struct {
		PartialSuccess *struct {
			RejectedLogRecords json.RawMessage `json:"rejectedLogRecords"`
		} `json:"partialSuccess"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&resp); err != nil || dec.More() {
		return 0, false
	}
	if resp.PartialSuccess == nil || len(resp.PartialSuccess.RejectedLogRecords) == 0 {
		return 0, true
	}
	// proto3 JSON writes int64 as a string, but accepts a number.
	raw := resp.PartialSuccess.RejectedLogRecords
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		raw = []byte(s)
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}
