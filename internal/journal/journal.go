// Package journal is the barmkin monitor's crash-safe record of session
// state. It holds only what crash recovery needs, and nothing a tool call
// carried: opaque session tokens, numeric uids, and values from closed sets.
//
// # Format
//
// A journal is a text file of records, one per line:
//
//	<crc32c of JSON, 8 lowercase hex digits> <JSON record>\n
//
// Each JSON record is a [Record]: a record version, a sequence number that
// starts at 1 and rises by one per line, a kind, and the fields that kind
// uses. Fields a kind does not use are zero.
//
//	start      the monitor began serving
//	shutdown   the monitor stopped cleanly
//	register   a session joined a root lineage, for a client uid and host
//	raise      a leg of a root lineage rose, naming the source that raised it
//
// Pass, warn and deny decisions, pre-registrations, screened content,
// commands, paths and reasons are never journaled.
//
// # Durability
//
// [Journal.Append] writes its records in one write and returns only after
// fsync, and the monitor answers the request that caused a record only after
// that. A crash can leave at most one unterminated fragment at the end of
// the file, from an append that was never acknowledged.
//
// # Replay
//
// [Load] reads a journal and reports what it found. A missing file is an
// empty journal. An unterminated tail is dropped and reported as Torn. A
// terminated line that fails its checksum, its sequence, its record version
// or its field checks is skipped and reported as Damaged; every other valid
// record is still returned, so the caller can keep the state they hold.
// Clean is true only when nothing was dropped and the last record is a
// shutdown, so a journal that does not end in a clean stop never reads as
// one. Deciding what an unclean or damaged journal means is the monitor's
// job, not this package's.
//
// # Compaction
//
// [Create] atomically replaces a journal with a new one holding the given
// records: it writes a temporary file in the same directory, fsyncs it,
// renames it over the journal and fsyncs the directory. The monitor uses it
// at every start to write a snapshot of its replayed state.
//
// # Permissions
//
// A journal file is created 0600 and must stay owned by the process's
// effective uid with no group or other access; [Load] refuses one that is
// not, or that is not a regular file, rather than trust state another user
// could have written. Symlinks are never followed.
package journal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"syscall"

	"github.com/Daviey/barmkin/internal/proto"
)

// RecordVersion is the only record version this package reads or writes.
const RecordVersion = 1

// MaxBytes bounds the journal Load reads. Compaction at every start keeps a
// journal to a few records per session, far below this.
const MaxBytes = 64 << 20

// Kind names what a record records.
type Kind string

const (
	KindStart    Kind = "start"
	KindShutdown Kind = "shutdown"
	KindRegister Kind = "register"
	KindRaise    Kind = "raise"
)

// Leg names one of a lineage's two legs.
type Leg string

const (
	LegUntrusted Leg = "untrusted"
	LegSensitive Leg = "sensitive"
)

// Record is one journal entry.
type Record struct {
	V       int          `json:"v"`
	Seq     uint64       `json:"seq"`
	Kind    Kind         `json:"kind"`
	UID     uint32       `json:"uid"`     // register, raise: the client's uid
	Host    proto.Host   `json:"host"`    // register, raise
	Session string       `json:"session"` // register
	Root    string       `json:"root"`    // register, raise: the lineage's root session
	Leg     Leg          `json:"leg"`     // raise
	Source  proto.Source `json:"source"`  // raise: the source that raised Leg
}

// Result is what Load found in a journal.
type Result struct {
	Records []Record
	Clean   bool // nothing was dropped and the last record is a shutdown
	Torn    bool // an unterminated tail was dropped
	Damaged bool // at least one terminated line was invalid and skipped
}

// Journal appends records to an open journal file.
type Journal struct {
	mu     sync.Mutex
	f      *os.File
	next   uint64
	broken error
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// tokenPattern matches internal/proto's opaque session token shape.
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// untrustedSources and sensitiveSources are the sources each leg can hold.
var (
	untrustedSources = []proto.Source{
		proto.SourceMCP, proto.SourceFetch, proto.SourceRead, proto.SourcePeer,
		proto.SourceSkill, proto.SourceInvisible, proto.SourceUnknownSession, proto.SourceMonitorRestart,
	}
	sensitiveSources = []proto.Source{proto.SourceCredential}
)

// SourceFits reports whether source may hold leg.
func SourceFits(leg Leg, source proto.Source) bool {
	switch leg {
	case LegUntrusted:
		return slices.Contains(untrustedSources, source)
	case LegSensitive:
		return slices.Contains(sensitiveSources, source)
	}
	return false
}

func validHost(h proto.Host) bool { return h == proto.HostClaudeCode || h == proto.HostOpenCode }

// Valid reports whether r is well formed apart from its sequence number.
func (r Record) Valid() bool {
	if r.V != RecordVersion {
		return false
	}
	switch r.Kind {
	case KindStart, KindShutdown:
		return r == Record{V: r.V, Seq: r.Seq, Kind: r.Kind}
	case KindRegister:
		return validHost(r.Host) && tokenPattern.MatchString(r.Session) &&
			tokenPattern.MatchString(r.Root) && r.Leg == "" && r.Source == ""
	case KindRaise:
		return validHost(r.Host) && r.Session == "" && tokenPattern.MatchString(r.Root) &&
			SourceFits(r.Leg, r.Source)
	}
	return false
}

// Load reads and checks the journal at path. See the package doc for what
// it reports. It fails, rather than report anything, when the file cannot
// be read or is not a private regular file of this uid.
func Load(path string) (Result, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Result{Clean: true}, nil
	}
	if err != nil {
		return Result{}, fmt.Errorf("open journal: %w", err)
	}
	defer f.Close()
	if err := checkPrivate(f); err != nil {
		return Result{}, fmt.Errorf("journal %s: %w", path, err)
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if err != nil {
		return Result{}, fmt.Errorf("read journal: %w", err)
	}
	if len(data) > MaxBytes {
		return Result{}, fmt.Errorf("journal %s is larger than %d bytes", path, MaxBytes)
	}
	return parse(data), nil
}

// parse splits data into records. See the package doc for its rules.
func parse(data []byte) Result {
	var res Result
	want := uint64(1)
	for len(data) > 0 {
		nl := bytes.IndexByte(data, '\n')
		if nl < 0 {
			res.Torn = true
			break
		}
		rec, err := parseLine(data[:nl])
		data = data[nl+1:]
		if err != nil {
			res.Damaged = true
			continue
		}
		if rec.Seq != want {
			res.Damaged = true
		}
		want = rec.Seq + 1
		res.Records = append(res.Records, rec)
	}
	n := len(res.Records)
	res.Clean = !res.Torn && !res.Damaged && (n == 0 || res.Records[n-1].Kind == KindShutdown)
	return res
}

func parseLine(line []byte) (Record, error) {
	sum, payload, ok := bytes.Cut(line, []byte{' '})
	if !ok || len(sum) != 8 {
		return Record{}, errors.New("missing checksum")
	}
	want, err := strconv.ParseUint(string(sum), 16, 32)
	if err != nil || crc32.Checksum(payload, castagnoli) != uint32(want) {
		return Record{}, errors.New("checksum mismatch")
	}
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil || dec.More() {
		return Record{}, errors.New("bad record")
	}
	if !rec.Valid() {
		return Record{}, errors.New("invalid record")
	}
	return rec, nil
}

// encode returns the journal lines for records, numbered from seq.
func encode(records []Record, seq uint64) ([]byte, error) {
	var buf []byte
	for _, r := range records {
		r.V, r.Seq = RecordVersion, seq
		if !r.Valid() {
			return nil, fmt.Errorf("invalid %s record", r.Kind)
		}
		payload, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		buf = fmt.Appendf(buf, "%08x %s\n", crc32.Checksum(payload, castagnoli), payload)
		seq++
	}
	return buf, nil
}

// Create atomically replaces the journal at path with one holding records,
// numbered from 1, and returns it open for appending. Record version and
// sequence numbers in records are ignored.
func Create(path string, records []Record) (*Journal, error) {
	data, err := encode(records, 1)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".journal-*")
	if err != nil {
		return nil, fmt.Errorf("create journal: %w", err)
	}
	defer os.Remove(tmp.Name()) // a no-op once renamed
	if err := writeSynced(tmp, data); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("replace journal: %w", err)
	}
	if err := SyncDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open journal: %w", err)
	}
	if err := checkPrivate(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("journal %s: %w", path, err)
	}
	return &Journal{f: f, next: uint64(len(records)) + 1}, nil
}

func writeSynced(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write journal: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync journal: %w", err)
	}
	return nil
}

// Append durably records records, in one write followed by fsync, and
// returns only after the fsync. After any failure the journal is broken
// and every later append fails, since the file's state is no longer known.
func (j *Journal) Append(records ...Record) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken != nil {
		return j.broken
	}
	data, err := encode(records, j.next)
	if err != nil {
		return err
	}
	if err := writeSynced(j.f, data); err != nil {
		j.broken = err
		return err
	}
	j.next += uint64(len(records))
	return nil
}

// Close closes the journal file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.broken == nil {
		j.broken = errors.New("journal closed")
	}
	return j.f.Close()
}

// checkPrivate requires f to be a regular file owned by this process's
// effective uid with no group or other permissions.
func checkPrivate(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	switch {
	case !fi.Mode().IsRegular():
		return errors.New("not a regular file")
	case !ok || int(st.Uid) != os.Geteuid():
		return errors.New("not owned by this uid")
	case fi.Mode().Perm()&0o077 != 0:
		return fmt.Errorf("mode %#o allows group or other access", fi.Mode().Perm())
	}
	return nil
}

// SyncDir fsyncs a directory, persisting the entries just created or
// renamed in it.
func SyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync dir: %w", err)
	}
	return nil
}
