package journal

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Daviey/barmkin/internal/proto"
)

func register(session, root string) Record {
	return Record{Kind: KindRegister, UID: 1000, Host: proto.HostClaudeCode, Session: session, Root: root}
}

func raise(root string, leg Leg, source proto.Source) Record {
	return Record{Kind: KindRaise, UID: 1000, Host: proto.HostClaudeCode, Root: root, Leg: leg, Source: source}
}

var sample = []Record{
	{Kind: KindStart},
	register("sess-a", "sess-a"),
	raise("sess-a", LegUntrusted, proto.SourceFetch),
	register("sess-b", "sess-a"),
	raise("sess-a", LegSensitive, proto.SourceCredential),
}

// kinds strips version and sequence numbers so records compare by content.
func kinds(rs []Record) []Record {
	out := make([]Record, len(rs))
	for i, r := range rs {
		r.V, r.Seq = 0, 0
		out[i] = r
	}
	return out
}

func journalPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "journal")
}

func mustCreate(t *testing.T, path string, records []Record) *Journal {
	t.Helper()
	j, err := Create(path, records)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

func mustLoad(t *testing.T, path string) Result {
	t.Helper()
	res, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCreateAppendLoad(t *testing.T) {
	path := journalPath(t)
	j := mustCreate(t, path, sample[:3])
	if err := j.Append(sample[3:]...); err != nil {
		t.Fatal(err)
	}
	if err := j.Append(Record{Kind: KindShutdown}); err != nil {
		t.Fatal(err)
	}

	res := mustLoad(t, path)
	want := append(slices.Clone(sample), Record{Kind: KindShutdown})
	if !slices.Equal(kinds(res.Records), want) {
		t.Fatalf("records = %+v\nwant %+v", res.Records, want)
	}
	for i, r := range res.Records {
		if r.Seq != uint64(i+1) || r.V != RecordVersion {
			t.Errorf("record %d: seq %d v %d", i, r.Seq, r.V)
		}
	}
	if !res.Clean || res.Torn || res.Damaged {
		t.Errorf("clean shutdown read as %+v", res)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("journal mode %#o, want 0600", fi.Mode().Perm())
	}
}

func TestMissingJournalIsEmpty(t *testing.T) {
	res := mustLoad(t, journalPath(t))
	if len(res.Records) != 0 || res.Torn || res.Damaged {
		t.Fatalf("missing journal read as %+v", res)
	}
}

func TestNoShutdownIsUnclean(t *testing.T) {
	path := journalPath(t)
	mustCreate(t, path, sample)
	res := mustLoad(t, path)
	if res.Clean || res.Torn || res.Damaged || len(res.Records) != len(sample) {
		t.Fatalf("journal without shutdown read as %+v", res)
	}
}

// A crash mid-append can cut the file at any byte. Every cut must replay as
// the records wholly before it, and never as a clean stop.
func TestTornTailAtEveryOffset(t *testing.T) {
	path := journalPath(t)
	mustCreate(t, path, append(slices.Clone(sample), Record{Kind: KindShutdown}))
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for cut := 1; cut < len(full); cut++ {
		res := parse(full[:cut])
		whole := bytes.Count(full[:cut], []byte{'\n'})
		if len(res.Records) != whole || res.Damaged {
			t.Fatalf("cut at %d: %d records (damaged %v), want %d", cut, len(res.Records), res.Damaged, whole)
		}
		if res.Clean {
			t.Fatalf("cut at %d read as a clean stop", cut)
		}
		if mid := cut > 0 && full[cut-1] != '\n'; res.Torn != mid {
			t.Fatalf("cut at %d: torn %v, want %v", cut, res.Torn, mid)
		}
	}
}

func TestDamagedLinesAreSkipped(t *testing.T) {
	path := journalPath(t)
	mustCreate(t, path, append(slices.Clone(sample), Record{Kind: KindShutdown}))
	full, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitAfter(full, []byte{'\n'})

	cases := map[string]func([][]byte){
		"flipped payload byte": func(ls [][]byte) { ls[2][12] ^= 0x01 },
		"flipped checksum":     func(ls [][]byte) { ls[2][0] ^= 0x01 },
		"missing checksum":     func(ls [][]byte) { ls[2] = ls[2][9:] },
		"dropped line":         func(ls [][]byte) { ls[2] = nil },
		"swapped lines":        func(ls [][]byte) { ls[2], ls[3] = ls[3], ls[2] },
	}
	for name, damage := range cases {
		t.Run(name, func(t *testing.T) {
			ls := make([][]byte, len(lines))
			for i, l := range lines {
				ls[i] = slices.Clone(l)
			}
			damage(ls)
			res := parse(bytes.Join(ls, nil))
			if !res.Damaged || res.Clean {
				t.Fatalf("damage not reported: %+v", res)
			}
			if len(res.Records) < len(sample)-1 {
				t.Fatalf("only %d records salvaged", len(res.Records))
			}
		})
	}
}

func TestInvalidRecordsAreDamage(t *testing.T) {
	bad := []Record{
		{Kind: "rotate"},
		{Kind: KindStart, UID: 7},
		{Kind: KindRegister, Host: "copilot", Session: "s", Root: "s"},
		{Kind: KindRegister, Host: proto.HostOpenCode, Session: "has space", Root: "s"},
		{Kind: KindRegister, Host: proto.HostOpenCode, Session: "s", Root: "s", Source: proto.SourceMCP},
		{Kind: KindRaise, Host: proto.HostOpenCode, Root: "s", Leg: LegUntrusted, Source: proto.SourceNone},
		{Kind: KindRaise, Host: proto.HostOpenCode, Root: "s", Leg: LegSensitive, Source: proto.SourceFetch},
		{Kind: KindRaise, Host: proto.HostOpenCode, Root: "s", Leg: LegUntrusted, Source: proto.SourceCredential},
		{Kind: KindRaise, Host: proto.HostOpenCode, Session: "s", Root: "s", Leg: LegUntrusted, Source: proto.SourceMCP},
	}
	for _, r := range bad {
		if _, err := encode([]Record{r}, 1); err == nil {
			t.Errorf("encoded invalid record %+v", r)
		}
		r.V, r.Seq = RecordVersion, 1
		if r.Valid() {
			t.Errorf("invalid record %+v reads as valid", r)
		}
	}
	if (Record{V: 2, Seq: 1, Kind: KindStart}).Valid() {
		t.Error("a future record version reads as valid")
	}
}

func TestLoadRefusesUnsafeFiles(t *testing.T) {
	dir := t.TempDir()

	wide := filepath.Join(dir, "wide")
	if err := os.WriteFile(wide, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wide, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(wide); err == nil {
		t.Error("loaded a group-readable journal")
	}

	link := filepath.Join(dir, "link")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err == nil {
		t.Error("followed a symlinked journal")
	}

	if _, err := Load(dir); err == nil {
		t.Error("loaded a directory as a journal")
	}
}

func TestCreateReplacesAtomically(t *testing.T) {
	path := journalPath(t)
	old := mustCreate(t, path, sample)
	mustCreate(t, path, []Record{{Kind: KindStart}})
	res := mustLoad(t, path)
	if len(res.Records) != 1 || res.Records[0].Seq != 1 {
		t.Fatalf("replaced journal holds %+v", res.Records)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("leftover files after replace: %v", entries)
	}
	// The old handle writes to the replaced file, never the new one.
	if err := old.Append(Record{Kind: KindShutdown}); err != nil {
		t.Fatal(err)
	}
	if n := len(mustLoad(t, path).Records); n != 1 {
		t.Errorf("an append through the old handle reached the new journal (%d records)", n)
	}
}

func TestBrokenJournalStaysBroken(t *testing.T) {
	j := mustCreate(t, journalPath(t), nil)
	j.f.Close() // the next write fails
	if err := j.Append(Record{Kind: KindStart}); err == nil {
		t.Fatal("append to a closed file succeeded")
	}
	if err := j.Append(Record{Kind: KindStart}); err == nil {
		t.Fatal("append after a failure succeeded")
	}
}

// The journal's closed sets must agree with the wire contract's.
func TestSourcesMatchProto(t *testing.T) {
	all := []proto.Source{
		proto.SourceNone, proto.SourceMCP, proto.SourceFetch, proto.SourceRead, proto.SourcePeer,
		proto.SourceSkill, proto.SourceInvisible, proto.SourceCredential,
		proto.SourceUnknownSession, proto.SourceMonitorRestart,
	}
	for _, s := range all {
		for _, leg := range []Leg{LegUntrusted, LegSensitive} {
			legs := proto.Legs{Untrusted: proto.SourceNone, Sensitive: proto.SourceNone}
			if leg == LegUntrusted {
				legs.Untrusted = s
			} else {
				legs.Sensitive = s
			}
			_, err := proto.Encode(&proto.ObserveResponse{Version: proto.Version, Legs: legs})
			wireOK := err == nil && s != proto.SourceNone
			if SourceFits(leg, s) != wireOK {
				t.Errorf("leg %s source %s: journal %v, wire %v", leg, s, SourceFits(leg, s), wireOK)
			}
		}
	}
}
