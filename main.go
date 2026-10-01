// Barmkin - lightweight regex guardrail for AI coding agents.
//
// Barmkin evaluates tool calls from Claude Code and opencode before they
// execute. It matches the command content against a set of regex rules
// and blocks (exit 2) or allows (exit 0) the call. No daemon, no network
// by default - just regex, sub-millisecond per evaluation. The optional
// dynamic layer (dynamic.go) can additionally escalate or deny gated
// shell commands via a hosted classifier.
//
// Usage:
//
//	barmkin eval        Read JSON from stdin, evaluate, exit 0 (allow) or 2 (deny)
//	barmkin test        Run built-in test vectors
//	barmkin validate    Check config: rule names, patterns, examples
//	barmkin stats       Aggregate decisions from the log file
//	barmkin version     Print version
//
// Config lookup order (first match wins):
//
//	$BARMKIN_CONFIG → /etc/barmkin/rules.yaml → ~/.barmkin/rules.yaml
//
// Hook protocol:
//
//	Claude Code pipes {"tool_name":"Bash","tool_input":{"command":"..."}}
//	to stdin of the configured hook command. Exit 0 allows the call;
//	exit 2 blocks it and stderr is shown to the LLM.
//
//	Opencode spawns barmkin eval as a subprocess from the TS plugin
//	(barmkin.ts) on every tool.execute.before event.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"time"
)

const version = "1.0.0"

// verbose enables stderr debug output when -v is passed.
var verbose bool

func main() {
	configPath, cmd := parseArgs(os.Args[1:])
	if configPath == "" {
		configPath = defaultConfigPath()
	}

	switch cmd {
	case "eval":
		cmdEval(configPath)
	case "validate":
		cmdValidate(configPath)
	case "test":
		cmdTest(configPath)
	case "stats":
		cmdStats(configPath)
	case "version":
		fmt.Printf("barmkin v%s\n", version)
	default:
		usage()
		os.Exit(1)
	}
}

// parseArgs extracts the global -config and -v flags from anywhere
// in the argument list. The first remaining positional argument is
// the subcommand. If no positional is given, defaults to "eval".
func parseArgs(args []string) (configPath, cmd string) {
	var positional []string
	for i := 0; i < len(args); {
		switch args[i] {
		case "-config":
			if i+1 >= len(args) {
				fatalf("-config requires a path")
			}
			configPath = args[i+1]
			i += 2
		case "-v", "--verbose":
			verbose = true
			i++
		default:
			positional = append(positional, args[i])
			i++
		}
	}
	if len(positional) > 0 {
		cmd = positional[0]
	} else {
		cmd = "eval"
	}
	return
}

// cmdEval is the primary hook entry point. It reads a JSON request from
// stdin (from Claude Code or the opencode TS plugin), evaluates it against
// all rules, and exits:
//
//	exit 0 - command allowed (silent)
//	exit 2 - command denied (reason written to stderr for the LLM)
//
// On config errors barmkin fails open (exit 0) so a misconfigured guardrail
// never blocks productive work.
//
// stdin read has a 2-second deadline to prevent a stuck pipe from
// freezing the agent.
func cmdEval(configPath string) {
	data, err := readStdinWithTimeout(2 * time.Second)
	if err != nil || len(data) == 0 {
		return
	}

	cfg, err := loadConfig(configPath)
	if err != nil {
		if verbose {
			fmt.Fprintf(os.Stderr, "[barmkin] config error: %v (failing open)\n", err)
		}
		return
	}

	engine := newEngine(cfg)
	defer engine.close()
	result := engine.evaluate(data)

	stdout, stderr, code := renderEvalOutput(result)
	if stdout != "" {
		fmt.Println(stdout)
	}
	if stderr != "" {
		fmt.Fprintln(os.Stderr, stderr)
	}
	if code != 0 {
		os.Exit(code)
	}
}

// renderEvalOutput maps a HookOutput to the hook's stdout, stderr and
// exit code. Escalate forces a Claude Code permission prompt even in
// auto mode (>= v2.1.211) via ask JSON with exit 0. Any other agent
// (e.g. the opencode plugin, which treats every exit 0 as allow) has
// no way to express an ask, so escalate is rendered as a deny there.
func renderEvalOutput(result HookOutput) (stdout, stderr string, code int) {
	switch {
	case result.Decision == "escalate" && result.Agent == "claude-code":
		return renderEscalateJSON(result.Reason), "", 0
	case result.Decision == "deny", result.Decision == "escalate":
		msg := result.Reason
		if msg == "" {
			msg = fmt.Sprintf("blocked by rule: %s", result.Rule)
		}
		return "", "[barmkin] " + msg, 2
	}
	return "", "", 0
}

// cmdValidate loads the config and reports:
//   - Each rule name with a checkmark or error
//   - Warnings for rules missing reason or example
//   - OTel and log status
//
// Exits 1 if any rule has an error (bad regex, missing name, duplicate).
func cmdValidate(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}

	fmt.Printf("config: %s\n", configPath)
	fmt.Printf("rules:  %d\n\n", len(cfg.Rules))

	seen := map[string]bool{}
	errs, warns := 0, 0

	for _, r := range cfg.Rules {
		switch {
		case r.Name == "":
			fmt.Printf("  ✗ <unnamed>: missing name\n")
			errs++
			continue
		case seen[r.Name]:
			fmt.Printf("  ✗ %s: duplicate rule name\n", r.Name)
			errs++
			continue
		case r.Pattern == "":
			fmt.Printf("  ✗ %s: empty pattern\n", r.Name)
			errs++
			seen[r.Name] = true
			continue
		case r.Reason == "":
			fmt.Printf("  ⚠ %s: no reason\n", r.Name)
			warns++
		case r.Example == "":
			fmt.Printf("  ⚠ %s: no example (not covered by test)\n", r.Name)
			warns++
		}
		seen[r.Name] = true
		fmt.Printf("  ✓ %s\n", r.Name)
	}

	fmt.Printf("\notel:    %s\n", otelStatus(cfg.OTel))
	fmt.Printf("log:     %s\n", logStatus(cfg.Log))
	fmt.Printf("dynamic: %s\n", dynamicStatus(cfg.Dynamic))
	if os.Getenv("BARMKIN_DYNAMIC") == "off" {
		fmt.Println("  (forced off by BARMKIN_DYNAMIC=off)")
	}
	if cfg.Dynamic.Enabled {
		validateDynamicAuth(cfg.Dynamic.Provider.Auth)
	}

	if warns > 0 {
		fmt.Printf("\n%d warning(s)\n", warns)
	}
	if errs > 0 {
		fmt.Printf("%d error(s) - config invalid\n", errs)
		os.Exit(1)
	}
	fmt.Println("config valid")
}

// cmdTest runs two built-in test vectors through the engine:
//
//	BARMKIN-TEST-DENY   - must match the test-deny rule (expected deny)
//	BARMKIN-TEST-ALLOW  - must not match any rule (expected allow)
//
// Test vectors do not write to the audit log. Exits 1 if any vector
// produces an unexpected result.
func cmdTest(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	cfg.Log.Path = "" // don't log test vectors

	vectors := []struct {
		label   string
		content string
		want    string
	}{
		{"deny", "BARMKIN-TEST-DENY", "deny"},
		{"allow", "BARMKIN-TEST-ALLOW", "allow"},
	}

	engine := newEngine(cfg)
	defer engine.close()

	passed := 0
	for _, v := range vectors {
		req := fmt.Sprintf(`{"tool":"bash","action":"test","args":{"command":%q}}`, v.content)
		resp := engine.evaluate([]byte(req))

		got := resp.Decision
		ok := got == v.want
		if ok {
			passed++
		}

		mark := "●"
		if !ok {
			mark = "✗"
		}

		detail := got
		if resp.Rule != "" {
			detail = fmt.Sprintf("%s (%s)", got, resp.Rule)
		}
		if !ok {
			detail += " - UNEXPECTED"
		}
		fmt.Printf("  %s  %-5s  %-20s  %s\n", mark, v.label, v.content, detail)
	}

	fmt.Printf("\n%d/%d passed", passed, len(vectors))
	if passed == len(vectors) {
		fmt.Println(" - barmkin is active")
	} else {
		fmt.Println(" - barmkin may be misconfigured")
		os.Exit(1)
	}
}

// statsSummary is the aggregated result of scanning the audit log.
// decision="allow" is Barmkin's wire value for Decision.Pass (see
// decision.go); escalate is counted separately rather than folded into
// allow (report.md §5f: "barmkin stats: count escalate separately...
// and stop counting non-deny as allow", the pre-existing main.go:285-91
// miscount this fixes).
type statsSummary struct {
	Events, Allows, Escalates, Denies int
	Hits                              map[string]int
	DynamicEvents, DynamicUnavailable int
	DynamicOutcomes                   map[string]int
	LatencyP50, LatencyP95            float64
	HasLatency                        bool
}

// computeStats scans the JSON-lines audit log at path and aggregates
// counts. Malformed lines are skipped, matching the log's own
// best-effort append semantics.
func computeStats(path string) (statsSummary, error) {
	sum := statsSummary{Hits: map[string]int{}, DynamicOutcomes: map[string]int{}}

	f, err := os.Open(path)
	if err != nil {
		return sum, err
	}
	defer f.Close()

	var latencies []float64

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 65536), 65536)
	for scanner.Scan() {
		var entry AuditEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			continue
		}
		sum.Events++
		switch entry.Decision {
		case "deny":
			sum.Denies++
			if entry.Rule != "" {
				sum.Hits[entry.Rule]++
			}
		case "escalate":
			sum.Escalates++
		default:
			sum.Allows++
		}

		if entry.Layer == "dynamic" && entry.Dynamic != nil {
			sum.DynamicEvents++
			sum.DynamicOutcomes[entry.Dynamic.Outcome]++
			if entry.Dynamic.Error != "" {
				sum.DynamicUnavailable++
			}
			if entry.Dynamic.LatencyMs > 0 {
				latencies = append(latencies, entry.Dynamic.LatencyMs)
			}
		}
	}

	if p50, p95, ok := latencyPercentiles(latencies); ok {
		sum.LatencyP50, sum.LatencyP95, sum.HasLatency = p50, p95, true
	}
	return sum, nil
}

// latencyPercentiles returns the p50/p95 of xs using the standard
// nearest-rank method (index = ceil(p*n)-1, clamped), so p95 of a
// 20-sample set is its max, not its 19th-of-20 value. ok is false for
// an empty input.
func latencyPercentiles(xs []float64) (p50, p95 float64, ok bool) {
	if len(xs) == 0 {
		return 0, 0, false
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	n := len(sorted)
	at := func(p float64) float64 {
		idx := int(math.Ceil(p*float64(n))) - 1
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		return sorted[idx]
	}
	return at(0.50), at(0.95), true
}

// cmdStats reads the JSON-lines log file and prints aggregated counts:
// total events, allows, escalates, denies, per-rule hit counts, and -
// when the dynamic layer produced any entries - its unavailable rate
// and latency percentiles (report.md §5f).
func cmdStats(configPath string) {
	cfg, err := loadConfig(configPath)
	if err != nil {
		fatalf("config: %v", err)
	}
	if cfg.Log.Path == "" {
		fmt.Println("logging disabled")
		return
	}

	sum, err := computeStats(cfg.Log.Path)
	if err != nil {
		fmt.Println("no log file")
		return
	}

	fmt.Printf("events:    %d\n", sum.Events)
	fmt.Printf("allows:    %d\n", sum.Allows)
	fmt.Printf("escalates: %d\n", sum.Escalates)
	fmt.Printf("denies:    %d\n", sum.Denies)
	if len(sum.Hits) > 0 {
		fmt.Println("hits:")
		rules := make([]string, 0, len(sum.Hits))
		for rule := range sum.Hits {
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		for _, rule := range rules {
			fmt.Printf("  %-24s %d\n", rule, sum.Hits[rule])
		}
	}

	if sum.DynamicEvents > 0 {
		fmt.Printf("\ndynamic:\n")
		fmt.Printf("  events:      %d\n", sum.DynamicEvents)
		fmt.Printf("  unavailable: %d (%.1f%%)\n", sum.DynamicUnavailable,
			100*float64(sum.DynamicUnavailable)/float64(sum.DynamicEvents))
		outcomes := make([]string, 0, len(sum.DynamicOutcomes))
		for o := range sum.DynamicOutcomes {
			outcomes = append(outcomes, o)
		}
		sort.Strings(outcomes)
		for _, o := range outcomes {
			fmt.Printf("  outcome %-10s %d\n", o, sum.DynamicOutcomes[o])
		}
		if sum.HasLatency {
			fmt.Printf("  latency p50: %.0fms\n", sum.LatencyP50)
			fmt.Printf("  latency p95: %.0fms\n", sum.LatencyP95)
		}
	}
}

// usage prints the help text to stderr.
func usage() {
	fmt.Fprint(os.Stderr, `barmkin v`+version+` - regex guardrail for coding agents

Usage: barmkin [-config <path>] [-v] <command>

Commands:
  eval       Evaluate from stdin (exit 2 = deny, exit 0 = allow)
  validate   Validate config file
  test       Run test vectors (deny + allow)
  stats      Show statistics from log file
  version    Print version
`)
}

// fatalf prints an error to stderr and exits 1.
func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[barmkin] "+format+"\n", args...)
	os.Exit(1)
}

// readStdinWithTimeout reads all of stdin, blocking at most timeout.
// If the deadline expires, returns whatever was read so far (possibly
// empty) and an error. This prevents a misconfigured hook or stuck
// pipe from freezing the agent indefinitely.
func readStdinWithTimeout(timeout time.Duration) ([]byte, error) {
	type result struct {
		data []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		data, err := io.ReadAll(os.Stdin)
		ch <- result{data, err}
	}()
	select {
	case r := <-ch:
		return r.data, r.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("stdin read timed out after %s", timeout)
	}
}
