// Package telemetry is the barmkin monitor's optional, content-free
// OpenTelemetry export of its journal's state changes. It is off unless
// root configures an OTLP/HTTP collector for the monitor, and the local
// journal stays the authoritative record either way.
//
// # What is exported
//
// One OTLP log record per state change the monitor has already made
// durable in its journal, and nothing else:
//
//	barmkin.monitor.start      the monitor began serving, with how its last run ended
//	barmkin.monitor.shutdown   the monitor stopped cleanly
//	barmkin.monitor.degraded   a change could not be journaled
//	barmkin.session.register   a session joined a lineage
//	barmkin.lineage.raise      a leg of a lineage rose, with the source that raised it
//	barmkin.export.loss        events this exporter dropped or could not deliver
//
// A record carries its time, its event code and values from closed sets
// (host, leg, source, recovery), and, for register and raise, a
// pseudonymous lineage identifier: a keyed hash of the client uid, host and
// root session token, under a key the monitor keeps in its state directory
// and never exports. The same lineage always maps to the same identifier,
// so a collector can correlate a lineage's events across restarts, but it
// cannot recover the uid or a session token from it. The resource names the
// service and its version, the shim-monitor protocol version, the journal
// record version and this package's schema version.
//
// Session tokens, uids, tool arguments, screened content, decisions,
// reasons, peer paths, credentials and journal bytes are never exported:
// the encoder copies only the fields listed above, by name, from each
// record.
//
// # Never in the way
//
// The monitor hands an event over only after its journal append has
// returned, so the export can never reorder or delay an fsync. The hand-off
// is a non-blocking send to a bounded queue: when the queue is full the
// event is dropped and counted. One background worker batches the queue
// and posts each batch with a deadline. A collector that is down, slow,
// refuses a batch or answers with something malformed only costs that
// batch, which is counted as failed; there is no retry and no buffer beyond
// the queue and one batch. Both counts are reported in a
// barmkin.export.loss record with the next batch the collector accepts, and
// the monitor logs when the export starts and stops failing. Nothing the
// collector does reaches a decision, the journal or the gate.
//
// # Configuration
//
// [LoadConfig] reads the monitor's export configuration, a JSON file that
// must be root's and writable by nobody else, in directories that are root's
// and writable by nobody else, so neither a client user nor the monitor's
// own service user can point the export somewhere else.
package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Configuration limits and defaults.
const (
	DefaultTimeout   = 2 * time.Second
	MaxTimeout       = 10 * time.Second
	DefaultQueueSize = 1024
	MaxQueueSize     = 65536
	DefaultMaxBatch  = 256
	MaxMaxBatch      = 1024
	DefaultInterval  = time.Second
	MinInterval      = 10 * time.Millisecond
	MaxInterval      = time.Minute

	maxConfigBytes = 64 << 10
)

// Config is how the monitor exports its journal events.
type Config struct {
	Endpoint  string        // the collector's OTLP/HTTP logs URL, e.g. http://127.0.0.1:4318/v1/logs
	Timeout   time.Duration // the deadline for one export request
	QueueSize int           // events held for export at most; more are dropped
	MaxBatch  int           // events sent in one request at most
	Interval  time.Duration // how long an event waits for a batch to fill
}

// file is the configuration file's format. Durations are milliseconds.
type file struct {
	Endpoint        string `json:"endpoint"`
	TimeoutMS       int    `json:"timeout_ms"`
	QueueSize       int    `json:"queue_size"`
	MaxBatch        int    `json:"max_batch"`
	FlushIntervalMS int    `json:"flush_interval_ms"`
}

// rootUID owns the configuration file and the directories above it.
// Replaceable in tests.
var rootUID = 0

// LoadConfig reads and checks the export configuration at path. It refuses
// a file that is not a regular file owned by root, that group or other can
// write, that sits under a directory not owned by root or writable by group
// or other (unless sticky), or that is reached through a symlink.
func LoadConfig(path string) (Config, error) {
	if !filepath.IsAbs(path) {
		return Config{}, errors.New("telemetry config path must be absolute")
	}
	path = filepath.Clean(path)
	if err := checkParents(path); err != nil {
		return Config{}, fmt.Errorf("telemetry config: %w", err)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return Config{}, fmt.Errorf("telemetry config: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("telemetry config: %w", err)
	}
	switch {
	case !fi.Mode().IsRegular():
		return Config{}, fmt.Errorf("telemetry config %s is not a regular file", path)
	case owner(fi) != rootUID:
		return Config{}, fmt.Errorf("telemetry config %s is not owned by root", path)
	case fi.Mode().Perm()&0o022 != 0:
		return Config{}, fmt.Errorf("telemetry config %s has mode %#o; group and other must not write it", path, fi.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("telemetry config: %w", err)
	}
	if len(data) > maxConfigBytes {
		return Config{}, fmt.Errorf("telemetry config %s is larger than %d bytes", path, maxConfigBytes)
	}
	cfg, err := parseConfig(data)
	if err != nil {
		return Config{}, fmt.Errorf("telemetry config %s: %w", path, err)
	}
	return cfg, nil
}

func parseConfig(data []byte) (Config, error) {
	var raw file
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("bad JSON: %w", err)
	}
	if dec.More() {
		return Config{}, errors.New("trailing data after the JSON object")
	}
	cfg := Config{
		Endpoint:  raw.Endpoint,
		Timeout:   time.Duration(raw.TimeoutMS) * time.Millisecond,
		QueueSize: raw.QueueSize,
		MaxBatch:  raw.MaxBatch,
		Interval:  time.Duration(raw.FlushIntervalMS) * time.Millisecond,
	}
	if raw.TimeoutMS < 0 || raw.QueueSize < 0 || raw.MaxBatch < 0 || raw.FlushIntervalMS < 0 {
		return Config{}, errors.New("limits must not be negative")
	}
	return cfg.withDefaults()
}

// withDefaults fills in the zero limits and checks every field.
func (c Config) withDefaults() (Config, error) {
	if err := checkEndpoint(c.Endpoint); err != nil {
		return Config{}, err
	}
	if c.Timeout == 0 {
		c.Timeout = DefaultTimeout
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.MaxBatch == 0 {
		c.MaxBatch = DefaultMaxBatch
	}
	if c.Interval == 0 {
		c.Interval = DefaultInterval
	}
	switch {
	case c.Timeout < time.Millisecond || c.Timeout > MaxTimeout:
		return Config{}, fmt.Errorf("timeout must be between 1ms and %s", MaxTimeout)
	case c.QueueSize < 1 || c.QueueSize > MaxQueueSize:
		return Config{}, fmt.Errorf("queue size must be between 1 and %d", MaxQueueSize)
	case c.MaxBatch < 1 || c.MaxBatch > MaxMaxBatch:
		return Config{}, fmt.Errorf("max batch must be between 1 and %d", MaxMaxBatch)
	case c.Interval < MinInterval || c.Interval > MaxInterval:
		return Config{}, fmt.Errorf("flush interval must be between %s and %s", MinInterval, MaxInterval)
	}
	return c, nil
}

// checkEndpoint accepts an absolute http or https URL with a host and no
// user information, query or fragment, so no credential rides in it.
func checkEndpoint(endpoint string) error {
	if endpoint == "" {
		return errors.New("an endpoint is required")
	}
	u, err := url.Parse(endpoint)
	switch {
	case err != nil:
		return fmt.Errorf("bad endpoint: %w", err)
	case u.Scheme != "http" && u.Scheme != "https":
		return errors.New("endpoint must be an http or https URL")
	case u.Host == "" || u.Hostname() == "":
		return errors.New("endpoint must name a host")
	case u.User != nil:
		return errors.New("endpoint must not carry user information")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "":
		return errors.New("endpoint must not carry a query or fragment")
	}
	return nil
}

// checkParents requires every directory above path to be a directory owned
// by root and writable by nobody else unless it is sticky.
func checkParents(path string) error {
	for p := filepath.Dir(path); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := fi.Mode()
		switch {
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", p)
		case owner(fi) != 0 && owner(fi) != rootUID:
			return fmt.Errorf("%s is owned by uid %d, not root", p, owner(fi))
		case mode.Perm()&0o022 != 0 && mode&os.ModeSticky == 0:
			return fmt.Errorf("%s is writable by group or other", p)
		}
		if p == filepath.Dir(p) {
			return nil
		}
	}
}

func owner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}
