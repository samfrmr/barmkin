package monitor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
)

// Journal is an append-only, crash-safe record of taint events.
//
// On-disk format: one record per line,
//
//	<crc32c of JSON, 8 lowercase hex digits> <JSON record>\n
//
// Each append is a single write followed by fsync, and the monitor only
// acknowledges a taint after that fsync returns. A crash can therefore
// leave at most one unterminated fragment at the end of the file - a
// record that was never acknowledged - which OpenJournal truncates.
// Any other damage (a terminated line that fails its checksum, a gap in
// sequence numbers, an unknown op) makes OpenJournal fail, so the monitor
// refuses to start and every client decision becomes a deny.
//
// The journal holds an exclusive flock for its lifetime, so two monitors
// cannot share one journal.
type Journal struct {
	mu     sync.Mutex
	f      *os.File
	next   uint64
	broken error
}

// Record is one journal entry. Only taint records exist in v1.
type Record struct {
	Seq     uint64      `json:"seq"`
	Op      string      `json:"op"`
	Session string      `json:"session"`
	Source  TaintSource `json:"source"`
}

const opTaint = "taint"

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// OpenJournal opens or creates the journal at path, replays it, and
// returns the records it holds. The caller must Close the journal.
func OpenJournal(path string) (*Journal, []Record, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open journal: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("lock journal %s (is another monitor running?): %w", path, err)
	}
	// Persist the directory entry in case this open created the file.
	if err := syncDir(filepath.Dir(path)); err != nil {
		f.Close()
		return nil, nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("read journal: %w", err)
	}
	records, valid, err := parseJournal(data)
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("journal %s: %w", path, err)
	}
	if valid < len(data) {
		// Drop the unacknowledged torn tail left by a crash mid-append.
		if err := f.Truncate(int64(valid)); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("truncate torn journal tail: %w", err)
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, nil, fmt.Errorf("sync journal: %w", err)
		}
	}

	return &Journal{f: f, next: uint64(len(records)) + 1}, records, nil
}

// parseJournal validates data and returns its records plus the length of
// the valid prefix. Only a final unterminated fragment may be invalid.
func parseJournal(data []byte) ([]Record, int, error) {
	var records []Record
	offset := 0
	for offset < len(data) {
		nl := bytes.IndexByte(data[offset:], '\n')
		if nl < 0 {
			return records, offset, nil // torn tail
		}
		line := data[offset : offset+nl]
		rec, err := parseRecord(line)
		if err != nil {
			return nil, 0, fmt.Errorf("record at byte %d: %w", offset, err)
		}
		if want := uint64(len(records)) + 1; rec.Seq != want {
			return nil, 0, fmt.Errorf("record at byte %d: seq %d, want %d", offset, rec.Seq, want)
		}
		records = append(records, rec)
		offset += nl + 1
	}
	return records, offset, nil
}

func parseRecord(line []byte) (Record, error) {
	sum, payload, ok := bytes.Cut(line, []byte{' '})
	if !ok || len(sum) != 8 {
		return Record{}, errors.New("missing checksum")
	}
	want, err := strconv.ParseUint(string(sum), 16, 32)
	if err != nil {
		return Record{}, errors.New("bad checksum field")
	}
	if crc32.Checksum(payload, castagnoli) != uint32(want) {
		return Record{}, errors.New("checksum mismatch")
	}
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return Record{}, fmt.Errorf("decode: %w", err)
	}
	if rec.Op != opTaint || !ValidSession(rec.Session) || !rec.Source.known() {
		return Record{}, errors.New("invalid record contents")
	}
	return rec, nil
}

// AppendTaint durably records a taint. It returns only after the record
// is fsynced. After any write or sync failure the journal is broken and
// every later append fails, since the on-disk state is no longer known.
func (j *Journal) AppendTaint(session string, source TaintSource) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken != nil {
		return j.broken
	}

	payload, err := json.Marshal(Record{Seq: j.next, Op: opTaint, Session: session, Source: source})
	if err != nil {
		return err
	}
	line := fmt.Appendf(nil, "%08x %s\n", crc32.Checksum(payload, castagnoli), payload)

	if _, err := j.f.Write(line); err != nil {
		j.broken = fmt.Errorf("journal write: %w", err)
		return j.broken
	}
	if err := j.f.Sync(); err != nil {
		j.broken = fmt.Errorf("journal sync: %w", err)
		return j.broken
	}
	j.next++
	return nil
}

// Close releases the journal file and its lock.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open journal dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync journal dir: %w", err)
	}
	return nil
}
