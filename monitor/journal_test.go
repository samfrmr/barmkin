package monitor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openTestJournal(t *testing.T, path string) (*Journal, []Record) {
	t.Helper()
	j, records, err := OpenJournal(path)
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	t.Cleanup(func() { j.Close() })
	return j, records
}

func TestJournalReplaysAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taint.journal")

	j, records := openTestJournal(t, path)
	if len(records) != 0 {
		t.Fatalf("new journal has %d records", len(records))
	}
	for _, s := range []string{"sess-a", "sess-b"} {
		if err := j.AppendTaint(s, SourceUntrustedInput); err != nil {
			t.Fatalf("AppendTaint(%s): %v", s, err)
		}
	}
	j.Close()

	j2, records := openTestJournal(t, path)
	if len(records) != 2 || records[0].Session != "sess-a" || records[1].Session != "sess-b" {
		t.Fatalf("replayed %+v", records)
	}
	// Appends continue the sequence after a reopen.
	if err := j2.AppendTaint("sess-c", SourceUntrustedInput); err != nil {
		t.Fatal(err)
	}
	j2.Close()
	_, records = openTestJournal(t, path)
	if len(records) != 3 || records[2].Seq != 3 {
		t.Fatalf("replayed %+v", records)
	}
}

func TestJournalTruncatesTornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taint.journal")
	j, _ := openTestJournal(t, path)
	if err := j.AppendTaint("sess-a", SourceUntrustedInput); err != nil {
		t.Fatal(err)
	}
	j.Close()

	good, _ := os.ReadFile(path)
	// Simulate a crash partway through the second append.
	torn := append(append([]byte{}, good...), []byte(`1234abcd {"seq":2,"op":"tai`)...)
	if err := os.WriteFile(path, torn, 0o600); err != nil {
		t.Fatal(err)
	}

	j2, records := openTestJournal(t, path)
	if len(records) != 1 || records[0].Session != "sess-a" {
		t.Fatalf("replayed %+v", records)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(good) {
		t.Fatalf("torn tail not truncated:\n%q", after)
	}
	if err := j2.AppendTaint("sess-b", SourceUntrustedInput); err != nil {
		t.Fatal(err)
	}
	j2.Close()
	if _, records = openTestJournal(t, path); len(records) != 2 {
		t.Fatalf("replayed %+v", records)
	}
}

func TestJournalRefusesDamage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taint.journal")
	j, _ := openTestJournal(t, path)
	j.AppendTaint("sess-a", SourceUntrustedInput)
	j.AppendTaint("sess-b", SourceUntrustedInput)
	j.Close()
	good, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(good), "\n")

	cases := map[string]string{
		"flipped byte":       strings.Replace(string(good), "sess-a", "sess-x", 1),
		"missing checksum":   strings.TrimPrefix(lines[0], lines[0][:9]) + lines[1],
		"sequence gap":       lines[1],
		"garbage line":       "not a journal line\n" + string(good),
		"terminated garbage": string(good) + "\x00\x00\x00\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "taint.journal")
			os.WriteFile(p, []byte(content), 0o600)
			if j, _, err := OpenJournal(p); err == nil {
				j.Close()
				t.Fatal("OpenJournal accepted a damaged journal")
			}
		})
	}
}

func TestJournalExclusiveLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taint.journal")
	openTestJournal(t, path)
	if j, _, err := OpenJournal(path); err == nil {
		j.Close()
		t.Fatal("second OpenJournal succeeded while the first holds the lock")
	}
}

func TestJournalBrokenAfterWriteFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taint.journal")
	j, _, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	j.f.Close() // make the next write fail
	if err := j.AppendTaint("sess-a", SourceUntrustedInput); err == nil {
		t.Fatal("append to closed file succeeded")
	}
	if err := j.AppendTaint("sess-b", SourceUntrustedInput); err == nil {
		t.Fatal("broken journal accepted a later append")
	}
}
