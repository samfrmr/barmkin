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
barmkin gate       managed Claude Code shim-presence check, exit 0 or exit 2
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

`cmd/barmkin-monitor` is a small local decision service for a future stateful barmkin. It is separate from `barmkin eval`. Only the Claude Code demo gate below calls it; `barmkin eval` and the default install do not.

It serves a versioned HTTP/JSON contract on a Unix socket (mode `0600`). Requests carry no tool content: only opaque session and tool-call tokens (`[A-Za-z0-9._-]{1,128}`) and values from closed enums. The typed definitions live in `monitor/api.go`.

| Endpoint | Request | Response |
|----------|---------|----------|
| `POST /v1/decide` | `{"version":1,"session":"s","operation":"routine"\|"protected"}` | `{"version":1,"decision":"allow"\|"deny","reason":"..."}` |
| `POST /v1/taint` | `{"version":1,"session":"s","source":"untrusted-input"}` | `{"version":1,"tainted":true\|false,"reason":"..."}` |
| `POST /v1/register` | `{"version":1,"session":"s","call":"c"}` | `{"version":1,"registered":true\|false,"reason":"..."}` |
| `POST /v1/presence` | `{"version":1,"session":"s","call":"c"}` | `{"version":1,"decision":"allow"\|"deny","reason":"..."}` |

Once a session is tainted, `protected` decisions in that session deny and `routine` ones still allow. There is no way to clear a taint yet; how a human clears one (or rotates to a new epoch) is still an open design choice.

`/v1/register` and `/v1/presence` back the Claude Code gate below. A registration is held in memory only, never journaled, and stays live for 10 seconds (`serve -presence-ttl`). A presence check allows only a live registration and consumes it, so each registration admits one call. An unregistered call denies with `unregistered`, an expired one with `expired`. Presence checks also deny while the monitor is refusing decisions after a journal failure. The monitor holds at most 4096 live registrations.

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

## Claude Code managed gate (demo)

This is a minimal demo of strict per-call shim presence for a managed Claude Code seat. Two hooks run on every tool call:

- **Shim plugin** (`plugins/claude-code/barmkin-shim`). Its PreToolUse hook (`node shim.ts`) sends the call's `session_id` and `tool_use_id` to the monitor (`POST /v1/register`). It always exits 0 and never blocks anything.
- **Managed gate** (`barmkin gate`). A PreToolUse hook in managed settings, so the user cannot remove it. It asks the monitor whether that exact call was registered (`POST /v1/presence`) and exits 0 only if it was.

A session without the shim, or with a broken one, can therefore run no tools. Both requests are versioned and content-free: they never carry the tool name, the tool input or the prompt.

Claude Code runs matching hooks in parallel, so the shim's registration can land just after the gate starts. The gate keeps asking for up to 1.5 seconds while the answer is `unregistered`. Every other answer is final.

The gate exits 2, writing its reason and the v1 response to stderr, for any of these:

- `unregistered`: no shim registration, or one that was already used.
- `expired`: the registration is older than its TTL.
- `malformed-request`: the hook input has no well-formed `session_id` or `tool_use_id`, is not JSON, is over 64 MiB, or does not arrive within 1 second. A bad gate flag also gives this reason.
- `malformed-response`: anything other than an HTTP 200 carrying a well-formed v1 allow.
- `monitor-unavailable`: no socket is configured (`-socket`, or `BARMKIN_MONITOR_SOCKET`), or the monitor is unreachable or stalls past the 500 ms request timeout.
- `deadline-exceeded`: the gate hits its 3-second hard deadline.

A panic inside the gate also denies, with exit 2.

Claude Code treats a hook timeout, and any exit code other than 0 or 2, as a non-blocking error and runs the tool anyway. So the gate never exits with any other code, and its 3-second deadline sits well inside the 10-second hook timeout in the recipe. `go test` checks the shipped recipe against the deadline.

This demo does not clear taints, rotate epochs or package anything, and it changes no host settings. The monitor socket is owner-only, so any process running as the same user can register calls. The demo shows that the shim is present on every call. It does not stop a same-user process from forging a registration.

### Lab fixture

```bash
./scripts/claude-gate-demo.sh     # or: make claude-gate-demo
```

The script builds `barmkin` and `barmkin-monitor` into a temporary directory and starts the monitor there. For each simulated tool call it feeds one PreToolUse input to `barmkin gate`. When the shim is "loaded", it also runs the plugin's own hook command from `hooks/hooks.json` on the same input, in parallel, as Claude Code does. It checks every exit code and reason:

- Without the shim, a call is denied.
- With the shim, a call is allowed, and the same call replayed or sent from another session is denied.
- A shim pointed at the wrong socket gets its call denied.
- An expired registration, malformed hook input, a gate with no socket, and a `SIGKILL`ed monitor are all denied.
- After a restart, calls are allowed again.

`go test .` runs this script and the shim's TypeScript tests. To run the TypeScript tests on their own, use `make shim-test`, or `node --test shim.test.ts` in the plugin directory. The shim needs Node 22.18+ or 23.6+, which run `.ts` files directly.

### Managed-settings recipe for the dedicated demo VM

These steps are for the dedicated demo VM only. Nothing in this repository applies them.

1. Install the binaries and the plugin marketplace:

   ```bash
   go build -o barmkin . && go build -o barmkin-monitor ./cmd/barmkin-monitor
   sudo install -m 0755 barmkin barmkin-monitor /usr/local/bin/
   sudo mkdir -p /opt/barmkin/plugins && sudo cp -r plugins/claude-code /opt/barmkin/plugins/
   ```

2. Run the monitor as the demo user. The socket directory must belong to that user:

   ```bash
   sudo install -d -o "$USER" -m 0700 /run/barmkin
   barmkin-monitor serve -socket /run/barmkin/monitor.sock -journal ~/.barmkin/taint.journal
   ```

3. Install [`plugins/claude-code/managed-settings.example.json`](plugins/claude-code/managed-settings.example.json) as `/etc/claude-code/managed-settings.json` (owned by root, mode `0644`). It sets up:
   - `hooks.PreToolUse`: the gate with matcher `*`, `-socket /run/barmkin/monitor.sock`, and `timeout: 10` (seconds).
   - `env.BARMKIN_MONITOR_SOCKET`: tells the shim where the monitor is.
   - `extraKnownMarketplaces` and `enabledPlugins`: declare the local `barmkin-local` marketplace at `/opt/barmkin/plugins/claude-code` and turn on `barmkin-shim@barmkin-local`.

   Do not set `allowManagedHooksOnly`. It also stops plugin hooks, so the shim would never register a call and the gate would deny everything.

4. Start `claude` as the demo user and confirm that tool calls run. To see the deny path, set `enabledPlugins."barmkin-shim@barmkin-local"` to `false`, or stop the monitor. Every tool call is then denied with the reason from the gate.

`claude plugin validate plugins/claude-code` checks the marketplace and plugin manifests.
