package monitor

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/Daviey/barmkin/internal/journal"
	"github.com/Daviey/barmkin/internal/proto"
	"github.com/Daviey/barmkin/internal/telemetry"
)

func TestServeExportsJournalEvents(t *testing.T) {
	cfg := deployment(t)
	col := newOTLPCollector(t)
	cfg.Telemetry, cfg.Version = telemetryConfig(col.URL+"/v1/logs"), "test"
	r := serve(t, cfg)
	c := newClient(cfg.Socket)
	c.must(t, proto.OpRegister, registerBody("s", true))
	c.must(t, proto.OpObserve, observeBody("s", proto.SourceFetch))
	c.must(t, proto.OpRegister, registerBody("t", true))
	r.shutdown(t)

	evs := col.events(t)
	want := []string{telemetry.EventStart, telemetry.EventRegister, telemetry.EventRaise, telemetry.EventRegister, telemetry.EventShutdown}
	if got := names(evs); !slices.Equal(got, want) {
		t.Fatalf("exported %v, want %v", got, want)
	}
	if evs[0].attrs["barmkin.recovery"] != "clean" || evs[2].attrs["barmkin.source"] != "fetch" {
		t.Errorf("events %+v", evs)
	}
	lineageT := evs[3].attrs["barmkin.lineage"]
	if fi, err := os.Lstat(filepath.Join(cfg.StateDir, "telemetry.key")); err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
		t.Errorf("telemetry key: %v %v", fi, err)
	}

	// Drop the clean stop, as a crash would: the next start exports the
	// monitor_restart raise of the lineage that was still clean, under the
	// same pseudonym, then an unclean start. "s" keeps its fetch.
	path := filepath.Join(cfg.StateDir, "journal")
	res, err := journal.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	j, err := journal.Create(path, res.Records[:len(res.Records)-1])
	if err != nil {
		t.Fatal(err)
	}
	j.Close()

	col2 := newOTLPCollector(t)
	cfg.Telemetry = telemetryConfig(col2.URL + "/v1/logs")
	serve(t, cfg).shutdown(t)
	evs = col2.events(t)
	if got := names(evs); !slices.Equal(got, []string{telemetry.EventRaise, telemetry.EventStart, telemetry.EventShutdown}) {
		t.Fatalf("exported after an unclean stop %v", got)
	}
	if evs[0].attrs["barmkin.source"] != "monitor_restart" || evs[0].attrs["barmkin.lineage"] != lineageT {
		t.Errorf("restart raise %+v, want lineage %s", evs[0], lineageT)
	}
	if evs[1].attrs["barmkin.recovery"] != "unclean" {
		t.Errorf("start %+v", evs[1])
	}
}

// TestServeWithCollectorDown serves with a collector that refuses every
// connection: the monitor serves and answers as it would without export,
// and stops promptly.
func TestServeWithCollectorDown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	endpoint := "http://" + ln.Addr().String() + "/v1/logs"
	ln.Close()

	answers := func(cfg Config) []string {
		r := serve(t, cfg)
		c := newClient(cfg.Socket)
		var out []string
		for _, req := range []struct {
			op   proto.Op
			body string
		}{
			{proto.OpHealth, `{"version":1}`},
			{proto.OpRegister, registerBody("s", true)},
			{proto.OpRegister, registerBody("u", false)},
			{proto.OpObserve, observeBody("s", proto.SourceMCP)},
			{proto.OpDecide, `{"version":1,"host":"claude_code","session":"s","classes":["dns"]}`},
			{proto.OpStatus, statusBody("u")},
			{proto.OpHealth, `{"version":1}`},
		} {
			status, out1, err := c.do(req.op, req.body)
			if err != nil {
				t.Fatalf("%s: %v", req.op, err)
			}
			out = append(out, fmt.Sprintf("%d %s", status, out1))
		}
		t0 := time.Now()
		r.shutdown(t)
		if took := time.Since(t0); took > 5*time.Second {
			t.Errorf("shutdown took %s with the collector down", took)
		}
		return out
	}
	want := answers(deployment(t))
	cfg := deployment(t)
	cfg.Telemetry = telemetryConfig(endpoint)
	if got := answers(cfg); !slices.Equal(got, want) {
		t.Errorf("answers with the collector down:\n got %v\nwant %v", got, want)
	}
}

func TestStartRefusesBadTelemetry(t *testing.T) {
	for name, setup := range map[string]func(cfg *Config){
		"no endpoint": func(cfg *Config) { cfg.Telemetry = &telemetry.Config{} },
		"key is a directory": func(cfg *Config) {
			cfg.Telemetry = telemetryConfig("http://127.0.0.1:1/v1/logs")
			os.Mkdir(filepath.Join(cfg.StateDir, "telemetry.key"), 0o700)
		},
		"key readable by group": func(cfg *Config) {
			cfg.Telemetry = telemetryConfig("http://127.0.0.1:1/v1/logs")
			key := filepath.Join(cfg.StateDir, "telemetry.key")
			os.WriteFile(key, make([]byte, telemetry.KeySize), 0o600)
			os.Chmod(key, 0o640)
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg := deployment(t)
			setup(&cfg)
			if m, err := Start(cfg); err == nil {
				m.Close()
				t.Fatal("started")
			}
			if _, err := os.Stat(cfg.Socket); err == nil {
				t.Error("left a socket behind")
			}
		})
	}
}
