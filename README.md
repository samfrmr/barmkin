# Barmkin

Regex guardrail for AI coding agents. Each tool call goes through `barmkin eval` before executing. If a rule matches, the command is blocked. Otherwise it passes silently.

Runs as a subprocess per invocation. Config is a YAML file of regex rules.

## Scope

Barmkin matches command strings. It does not read file contents or inspect command output. If you need semantic evaluation of what an agent writes or retrieves, use sondera, which adds Cedar policies and LLM classification on top.

## Why the name?

A barmkin is a Scottish defensive wall around a tower house. My friend Sam, who is very Scottish, tells me his ancestors built these to keep my ancestors out. I'm choosing to read that as a compliment about our taste in architecture, our shared desire to try deep-fried battered Mars bars, and our mutual appreciation of Buckfast.

Had this been a network service, it would have listened on port 1707. Sam will know why. I do like Sam.

## Install

```bash
go build -o barmkin .
sudo ./install.sh
```

This puts the binary in `~/.local/bin/`, the config in `/etc/barmkin/rules.yaml`, and registers hooks for both Claude Code and opencode.

### Claude Code

A PreToolUse hook in `~/.claude/settings.json` runs `barmkin eval` on every `Bash`, `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` call. Exit 2 blocks and stderr goes to the LLM.

### opencode

The plugin at `plugins/barmkin.ts` spawns `barmkin eval` on every `tool.execute.before` event. Installed to `~/.config/opencode/plugins/`.

## Commands

```
barmkin eval       stdin in, exit 0 or exit 2
barmkin test       run deny/allow test vectors
barmkin validate   check config, rules, examples
barmkin stats      aggregate from log file
barmkin version
```

## Rules

45 rules across 9 categories. Every rule has an `example` field that `go test` verifies automatically. Adding a rule with an example adds a test.

| Category | Rules |
|----------|-------|
| Destructive | rm-rf, chmod 777, fork bomb, shutdown, kill -9 -1, shred, mkfs, dd, wipefs, redirect to device |
| Git | reset --hard, push --force, clean -fd, filter-branch |
| Database | TRUNCATE TABLE, DROP TABLE, DROP DATABASE, DELETE without WHERE |
| Exfiltration | curl\|bash, wget\|bash, scp ssh keys, curl upload, tar\|ssh, nc pipe, rsync remote |
| Supply chain | npm git+ install, pip untrusted URL |
| Obfuscation | base64+exec, eval hex |
| Secrets | AWS keys, private keys, GitHub/Slack/GitLab tokens, .env files |
| Persistence | authorized_keys, chown system, ssh tunnel, history clear |
| Container | docker prune --all, docker rm all, kubectl delete namespace |

## Adding rules

Edit `/etc/barmkin/rules.yaml`:

```yaml
- name: "my-rule"
  pattern: 'dangerous\s+command'
  action: "deny"                      # or "allow" to override deny rules
  reason: "Why it's blocked"
  example: "dangerous command --flag"  # must match, verified by tests
```

Run `barmkin validate` after editing.

### Allow rules

Setting `action: "allow"` on a rule overrides all deny rules, regardless of ordering. Use this to exempt specific patterns:

```yaml
- name: "allow-tmp-rm"
  pattern: 'rm\s+-rf\s+/tmp/'
  action: "allow"

- name: "rm-rf-force"
  pattern: 'rm\s+-rf\b'
```

`rm -rf /tmp/build` passes. `rm -rf /home` does not.

## opencode env vars

| Variable | Default | Description |
|----------|---------|-------------|
| `BARMKIN_BIN` | `barmkin` | Binary path |
| `BARMKIN_TITLE` | `Barmkin` | Toast title (if toasts on) |
| `BARMKIN_TOAST` | `0` | `1` enables toast notifications |
| `BARMKIN_DRY_RUN` | `0` | `1` logs denials without blocking |
| `BARMKIN_OFF` | `0` | `1` disables the plugin |

## Logging

Each evaluation appends a JSON line to `~/.barmkin/barmkin.log`:

```json
{"ts":"2026-06-30T01:00:00Z","trajectory_id":"sess-123","tool":"bash","action":"ShellCommand","decision":"deny","reason":"Recursive force-delete","duration_ms":0.064,"rule":"rm-rf-force","content":"rm -rf /tmp","agent":"claude-code"}
```

`barmkin stats` aggregates. The format matches sondera's AuditEntry if you want to query both together.

## OpenTelemetry

Set `otel.endpoint` in rules.yaml to send one span per evaluation to an OTLP collector:

```yaml
otel:
  endpoint: "localhost:4317"
  service: "barmkin"
```

## Local monitor (foundation)

`cmd/barmkin-monitor` is a small local decision service for a future stateful barmkin. It is separate from `barmkin eval` and nothing calls it yet; no hooks, plugins or settings use it.

It serves a versioned HTTP/JSON contract on a Unix socket (mode `0600`). Requests carry no tool content: only an opaque session token (`[A-Za-z0-9._-]{1,128}`) and values from closed enums. The typed definitions live in `monitor/api.go`.

| Endpoint | Request | Response |
|----------|---------|----------|
| `POST /v1/decide` | `{"version":1,"session":"s","operation":"routine"\|"protected"}` | `{"version":1,"decision":"allow"\|"deny","reason":"..."}` |
| `POST /v1/taint` | `{"version":1,"session":"s","source":"untrusted-input"}` | `{"version":1,"tainted":true\|false,"reason":"..."}` |

Once a session is tainted, `protected` decisions in that session deny and `routine` ones still allow. There is no way to clear a taint yet; how a human clears one (or rotates to a new epoch) is still an open design choice.

Failures deny:

- Invalid JSON, unknown or repeated keys, case-variant keys, trailing data, oversized bodies, the wrong method, an unsupported `version`, an unknown `operation` or `source`, and unknown paths all deny with a reason code.
- The client (`monitor.Client`, and the `decide` and `send` subcommands) treats anything other than an HTTP 200 carrying a well-formed v1 allow as a deny. If the monitor is unreachable, the result is `monitor-unavailable`.
- If a taint cannot be journaled, the monitor denies every later decision.

Taints are written to an append-only journal. Each record carries a CRC-32C checksum and is fsynced before the taint is acknowledged, so an acknowledged taint survives a crash or `SIGKILL`. On startup the monitor replays the journal and drops only an unterminated final fragment (an append that was interrupted before it was acknowledged). Any other damage stops the monitor from starting, and every client decision then denies. An exclusive `flock` keeps a second monitor off the same journal.

### Demo

```bash
./scripts/monitor-demo.sh     # or: make monitor-demo
```

The script builds `barmkin-monitor` into a temporary directory and starts it there. It checks clean-session allows, malformed and unknown requests, a taint through `/v1/taint`, a `SIGKILL` of the monitor (all decisions deny while it is down), and a restart in which the journaled taint still denies `protected`. It checks every exit code and reason and exits non-zero on the first surprise. `go test ./cmd/barmkin-monitor` runs the same script.

To drive it by hand:

```bash
go build -o /tmp/barmkin-monitor ./cmd/barmkin-monitor
/tmp/barmkin-monitor serve -socket /tmp/bm.sock -journal /tmp/bm.journal & sleep 1
/tmp/barmkin-monitor decide -socket /tmp/bm.sock -session s1 -operation protected   # exit 0, allow
/tmp/barmkin-monitor taint  -socket /tmp/bm.sock -session s1                         # exit 0, recorded
/tmp/barmkin-monitor decide -socket /tmp/bm.sock -session s1 -operation protected   # exit 2, tainted
/tmp/barmkin-monitor send   -socket /tmp/bm.sock -path /v1/decide -body '{"bad":1}'  # exit 2, malformed-request
kill -9 %1; /tmp/barmkin-monitor serve -socket /tmp/bm.sock -journal /tmp/bm.journal & sleep 1
/tmp/barmkin-monitor decide -socket /tmp/bm.sock -session s1 -operation protected   # exit 2, still tainted
```
