# Barmkin

Guardrails for AI coding agents, in two generations:

- **`barmkin eval`** is the original regex guardrail. Each tool call passes through it before it runs, and a matching rule blocks the call. It runs as one subprocess per call, with no daemon and no network.
- **The successor** is a stateful guard. `barmkin monitor` is a root-managed service that keeps each session's taint in a crash-safe journal. A shim inside the agent reports to it: [a Claude Code shim](#claude-code-shim-and-managed-gate) behind a managed gate (`barmkin gate`), or [an OpenCode 2.x shim](#opencode-2x-shim).

> [!NOTE]
> The two generations do not share anything at run time. `barmkin eval` does not use the monitor, and `install.sh` installs only `barmkin eval`. [`packaging/`](#packaging) installs the monitor and the managed Claude Code seat on a dedicated host.

## Contents

- [Commands](#commands)
- [Regex guardrail (`barmkin eval`)](#regex-guardrail-barmkin-eval)
- [Monitor (`barmkin monitor`)](#monitor-barmkin-monitor)
- [Claude Code shim and managed gate](#claude-code-shim-and-managed-gate)
- [OpenCode 2.x shim](#opencode-2x-shim)
- [Packaging](#packaging)
- [Development](#development)
- [Why the name?](#why-the-name)

## Commands

```
barmkin [-config PATH] [-v] <command>

eval       read a tool call on stdin; exit 0 allows, exit 2 denies (the default command)
validate   check the config: rule names, patterns and examples
test       run the deny and allow test vectors
stats      aggregate decisions from the log file
gate       managed Claude Code PreToolUse check for shim presence, exit 0 or 2
monitor    run the monitor service
monitor-admin list|clear   root only: list monitor lineages, or clear one (see "Administrative clear (opt-in)")
version    print the version
```

Requires Go 1.26 to build.

## Regex guardrail (`barmkin eval`)

Barmkin `eval` matches command strings against regex rules. It does not read file contents or inspect command output. For semantic evaluation of what an agent writes or retrieves, use sondera, which adds Cedar policies and LLM classification.

### Install

```bash
go build -o barmkin .
./install.sh            # or: ./install.sh claude | opencode
```

`install.sh` copies the binary to `~/.local/bin/barmkin` and the rules to `/etc/barmkin/rules.yaml` (using `sudo` for that step). It then registers barmkin with each agent:

- **Claude Code**: a PreToolUse hook with matcher `*` in `~/.claude/settings.json`, merged with your existing hooks (needs `jq`). Exit 2 blocks the call, and stderr goes to the model.
- **opencode 1.x**: [`plugins/barmkin.ts`](plugins/barmkin.ts), copied to `~/.config/opencode/plugins/`, spawns `barmkin eval` on every `tool.execute.before` event. It has the OpenCode 1.x plugin shape, which OpenCode 2.x rejects; see the [OpenCode 2.x shim](#opencode-2x-shim).

The config is read from `$BARMKIN_CONFIG`, then `/etc/barmkin/rules.yaml`, then `~/.barmkin/rules.yaml`.

### Rules

[`rules.yaml`](rules.yaml) ships 44 deny rules and one test vector:

| Category | Rules |
|----------|-------|
| Destructive | rm -rf, chmod 777, fork bomb, shutdown, kill -9 -1, shred, mkfs, dd, wipefs, redirect to device |
| Git | reset --hard, push --force, clean -fd, filter-branch |
| Database | TRUNCATE TABLE, DROP TABLE, DROP DATABASE, DELETE without WHERE |
| Exfiltration | curl\|bash, wget\|bash, scp ssh keys, curl upload, tar\|ssh, nc pipe, rsync remote |
| Supply chain | npm git+ install, pip untrusted URL |
| Obfuscation | base64+exec, eval hex |
| Secrets | AWS keys, private keys, GitHub, Slack and GitLab tokens, .env files |
| Persistence | authorized_keys, chown system, ssh tunnel, history clear |
| Container | docker prune --all, docker rm all, kubectl delete namespace |

Add a rule to `/etc/barmkin/rules.yaml`, then run `barmkin validate`:

```yaml
- name: "my-rule"
  pattern: 'dangerous\s+command'       # Go (RE2) regex
  action: "deny"                       # or "allow"
  secret: false                        # true: redact this rule's matches from the log
  reason: "Why it's blocked"
  example: "dangerous command --flag"  # must match; go test and barmkin test check it
```

An **allow rule** exempts only the deny matches that lie entirely inside one of its own matches, whatever the rule order. With an allow rule for `rm\s+-rf\s+/tmp/`, `rm -rf /tmp/build` passes, but `rm -rf /tmp/build; rm -rf ~` is still denied by the `rm -rf ~` part. Without allow rules, the first matching deny rule wins.

### opencode plugin variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BARMKIN_BIN` | `barmkin` | Binary path |
| `BARMKIN_TOAST` | `0` | `1` enables toast notifications |
| `BARMKIN_TITLE` | `Barmkin` | Toast title |
| `BARMKIN_DRY_RUN` | `0` | `1` logs denials without blocking |
| `BARMKIN_OFF` | `0` | `1` disables the plugin |

### Logging and telemetry

Each evaluation appends a JSON line to `~/.barmkin/barmkin.log` (set by `log.path`), in the same format as sondera's AuditEntry. `barmkin stats` aggregates it.

```json
{"ts":"2026-06-30T01:00:00Z","trajectory_id":"sess-123","tool":"bash","action":"ShellCommand","decision":"deny","reason":"Recursive force-delete","duration_ms":0.064,"rule":"rm-rf-force","content":"rm -rf /tmp","agent":"claude-code"}
```

`content` holds the first 80 characters of the command. Matches of every `secret: true` rule are replaced with `[REDACTED:<rule>]` first, so a blocked secret never reaches the log.

To send one OpenTelemetry span per evaluation to an OTLP collector, set `otel.endpoint` in `rules.yaml`:

```yaml
otel:
  endpoint: "localhost:4317"
  service: "barmkin"
```

## Monitor (`barmkin monitor`)

The successor's monitor ([`internal/monitor`](internal/monitor)) serves the versioned shim-monitor contract ([`internal/proto`](internal/proto)): JSON over HTTP POST to `/v1/<op>` on a Unix socket. It keeps each session's taint in a crash-safe journal ([`internal/journal`](internal/journal)).

```
barmkin monitor [-socket /run/barmkin/monitor.sock] [-state-dir /var/lib/barmkin]
                [-client-group barmkin-clients] [-preregister-ttl 10s]
                [-admin-socket /run/barmkin-admin/admin.sock]
                [-telemetry-config /etc/barmkin/monitor-telemetry.json]
```

**Deployment.** The monitor runs as a dedicated service user under a root-managed systemd unit ([`packaging/`](#packaging)). It refuses to start if:

- it runs as root;
- its state directory is not the service user's with mode `0700` or tighter;
- its runtime directory is not the service user's with mode `0750` or tighter;
- a parent directory is writable by anyone other than root or the service user;
- any path component is a symlink.

The journal is `0600`. The socket is `0660`, group `barmkin-clients`. The monitor identifies every connection by its peer credentials (`SO_PEERCRED`), and a session key includes the client's uid, so one user cannot touch another's sessions.

**Sessions and taint.** Each session belongs to a root lineage that holds two legs, *untrusted* and *sensitive*. Legs only rise, and the first source to raise a leg stays. Nothing a client sends lowers a leg: the shim contract has no clear, rotate or capability operation. The only way down is root's [administrative clear](#administrative-clear-opt-in), which is off by default.

- `register` refuses a host whose sandbox is off or allows every Unix socket (`posture_refused`).
- Only a fresh top-level session starts clean. Any other new lineage starts with its untrusted leg raised by `unknown_session`, and every operation on an unregistered session fails `unknown_session`.
- `decide` applies the egress postures: with the untrusted leg up it denies the deny classes and warns on the rest; with both legs up it denies everything; a clean session gets warnings only for destructive classes.

**Journal.** A leg raise, registration or administrative clear is fsynced before the reply. At start the monitor replays the journal and compacts it. After an unclean stop (a crash, `SIGKILL` or a damaged record), every known lineage gets its untrusted leg raised by `monitor_restart`. A damaged journal is moved aside, and only its valid records are replayed. A journal with the wrong owner or mode, or one that is a symlink or not a regular file, stops the monitor from starting. If a change cannot be journaled, `health` reports `degraded` and every other operation fails `unavailable`.

> [!IMPORTANT]
> The screen service ([`internal/screen`](internal/screen), the Jev screen ported from barmkin-mod) is not wired into the monitor yet. Until it is, `/v1/screen` raises the untrusted leg for the content's source and answers `unavailable`, so both shims withhold all untrusted content.

### Administrative clear (opt-in)

Root can clear one lineage's taint through a separate, root-owned administrative socket. It is off by default: without it the taint is sticky, and nothing lowers a leg. There is no automatic clear, and no Claude Code or OpenCode command clears.

**Clearing monitor state does not remove untrusted material already in an AI conversation.** Whatever the session read, a prompt injection included, is still in its context after a clear and can still steer it. Clear a lineage only when you have checked what raised its legs.

**The socket.** systemd, as root, creates `/run/barmkin-admin` (`root:root`, `0700`) and the socket `admin.sock` in it (`root:root`, `0600`) from `packaging/systemd/barmkin-monitor-admin.socket`, and passes it to the monitor by socket activation. The drop-in `barmkin-monitor-admin.conf` adds `-admin-socket /run/barmkin-admin/admin.sock` to the monitor's command. The monitor never creates this socket itself. It refuses to start with `-admin-socket` unless systemd passed it the socket, and unless the directory is root's with no group or other access. It reads every connection's peer credentials (`SO_PEERCRED`) and closes any connection that is not from root before reading it. A request from another uid gets `forbidden`. The client socket answers none of the administrative paths (`/admin/v1/list`, `/admin/v1/clear`), so no shim, plugin, MCP server, managed gate or ordinary user can reach them. The contract is in [`internal/admin`](internal/admin/admin.go).

**The command.** Root runs `barmkin monitor-admin`:

```
barmkin monitor-admin list  [-admin-socket PATH] [-json]
barmkin monitor-admin clear -uid UID -host claude_code|opencode -lineage ID \
                            -reason false_positive|reviewed_safe|monitor_recovery [-admin-socket PATH]
```

- `list` shows each lineage without content: the opaque lineage id, the client's uid and host, the epoch, each leg with the closed source that raised it and when, the session ids, and every earlier clear with the legs it lowered.
- `clear` names one lineage exactly. A subagent's session id, another uid or another host is refused. The reason is one of three fixed codes, never free text. `clear` needs a terminal on standard input. It shows the lineage and the warning above, and clears only when you type the lineage id back. It sends the epoch and legs it showed, so if the lineage has changed since, the monitor refuses the clear (`mismatch`). Both subcommands refuse to run as anyone but root, or to talk to a socket that is not root's in a directory only root can enter.

**What a clear does.** The monitor appends a `clear` record to the journal (lineage, new epoch, reason, time) and fsyncs it before it lowers the legs or answers. If the journal cannot take the record, nothing is lowered and the monitor degrades. The cleared raises stay in the journal and in `list` as history. The monitor drops every pre-registration of the lineage's sessions, so each session gets `unknown_session` on its next request until it registers again in the new epoch; both shims re-register on that error. Legs can rise again as usual. Each clear is logged, and clear records are never exported through OpenTelemetry. A clear survives a clean restart. After a crash, `monitor_restart` taints every lineage again, as it always does.

**Turning it on.** On Debian and Ubuntu, `sudo packaging/install.sh install --admin-socket`; running `install` again without it removes the socket. On NixOS, set `services.barmkin.adminSocket.enable = true;`, which also puts `barmkin` on root's system `PATH`; switching back removes the socket, though the empty root-only `/run/barmkin-admin` stays until reboot. Root is trusted here as everywhere: a process running as root can talk to the socket without a terminal, so never run an agent as root.

### Telemetry export

Export is off unless `-telemetry-config` names a root-owned file that group and other cannot write, in directories only root can write:

```json
{
  "endpoint": "http://127.0.0.1:4318/v1/logs",
  "timeout_ms": 2000,
  "queue_size": 1024,
  "max_batch": 256,
  "flush_interval_ms": 1000
}
```

Only `endpoint` is required. It is an OTLP/HTTP JSON logs URL, with no user info, query or fragment. The other fields show their defaults. The monitor ([`internal/telemetry`](internal/telemetry)) exports one log record per journaled change: monitor start (with its recovery kind), shutdown and degraded state, session registration and leg raises. A lineage is named by a keyed HMAC pseudonym, and the key is kept as `telemetry.key` in the state directory. Session tokens, uids, tool arguments, content, decisions, reasons and credentials are never exported.

Export never blocks the monitor. Events go to a bounded queue and are dropped (and counted) when it is full. Each batch gets one try, with no retry or redirect. Losses are reported in a later `barmkin.export.loss` record.

The packaged unit allows only Unix sockets, so export needs a drop-in such as `/etc/systemd/system/barmkin-monitor.service.d/telemetry.conf`:

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/barmkin monitor -socket /run/barmkin/monitor.sock -state-dir /var/lib/barmkin -client-group barmkin-clients -telemetry-config /etc/barmkin/monitor-telemetry.json
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

## Claude Code shim and managed gate

A managed Claude Code seat runs two pieces in every session, and both talk to the monitor:

- **The shim** ([`plugins/claude-code/barmkin-shim`](plugins/claude-code/barmkin-shim)) is a hooks module ported from barmkin-mod. It registers the session along with its sandbox posture, and it pre-registers each `tool_use_id` before Claude Code runs the call. It classifies egress-capable calls (shell, web fetch and search, MCP, Monitor WebSockets, persistence-file writes, skill loads) so the monitor can decide on them. It also redacts untrusted content into windows for `/v1/screen` and reports credential paths, credential-shaped values and hidden text as leg raises. Locally it does secret redaction, the invisible-text scrub, MCP description hardening with a per-server allowlist (`mcp_server_allowlist`), the skill-listing guard, outbound DLP, the posture warnings, the HUD band and `/barmkin-status`.
- **The gate** (`barmkin gate`) is a managed PreToolUse hook on every tool. It reads only `session_id` and `tool_use_id`, and it allows a call only if the shim pre-registered that exact call (`/v1/gate`). A session without a working shim can run no tools: the deny says `barmkin shim not present`.

The taint is sticky: no prompt, command, compaction or `/clear` lowers a leg. Only root's opt-in [administrative clear](#administrative-clear-opt-in) does, and the shim then re-registers the session when the monitor answers `unknown_session`. Failure denies: every shim request has a 1-second deadline, and a timeout, error, malformed reply or contract-version mismatch denies the step it guards.

The gate exits 2, with its reason on stderr, for `unregistered`, `unknown-session`, `malformed-request`, `malformed-response`, `version-mismatch`, `monitor-unavailable`, `monitor-uid-mismatch` (when `-monitor-uid` pins the monitor's uid) and `deadline-exceeded` (3 seconds). It never exits with any other code, because Claude Code would treat that as a non-blocking error. Built static, the gate costs about 4 ms per call at p50.

> [!WARNING]
> The shim must be a hooks module. Claude Code 2.1.x runs the managed PreToolUse hook before any plugin hook, so a shim written as a plugin PreToolUse command hook never pre-registers in time, and every call is denied. A process in the `barmkin-clients` group outside the sandbox could still forge a pre-registration, and the TypeScript shim cannot pin the monitor's uid.

### The managed-settings recipe

[`plugins/claude-code/managed-settings.example.json`](plugins/claude-code/managed-settings.example.json) is what the installers write as `/etc/claude-code/managed-settings.json`. It sets the full lock:

- `allowManagedHooksOnly: true`: user, project, local and `--settings` hooks, `--plugin-dir` mods and user-installed plugins do not load.
- `prependPlugins`: seats `barmkin-shim@barmkin-local`, then `cc-plugin-sec-default@builtin`. Keep the security default listed by that exact id, or it is unseated.
- `extraKnownMarketplaces` and `enabledPlugins`: the local `barmkin-local` marketplace at `/opt/barmkin/plugins/claude-code`, with the shim turned on.
- `sandbox`: enabled, `failIfUnavailable`, `allowUnsandboxedCommands: false`, with `bwrapPath` and `socatPath` pinned to `/usr/bin`. Never set `network.allowAllUnixSockets`; the monitor refuses such sessions.
- `hooks.PreToolUse`: the gate with matcher `*`, `-socket /run/barmkin/monitor.sock` and `timeout: 10`. The installers append `-monitor-uid`.
- `env.BARMKIN_MONITOR_SOCKET`: where the shim finds the monitor.

Managed settings lock every Claude Code user on the machine, so install the seat only on a dedicated host. The lock holds against the user's own settings, mods and plugins, but not against root.

## OpenCode 2.x shim

[`shims/opencode`](shims/opencode/README.md) is the `barmkin-opencode` plugin for OpenCode 2.x, ported from barmkin-mod. Each OpenCode session registers in its root session's lineage, so subagents share their parent's legs, and the taint survives an OpenCode restart. The taint is sticky; only root's opt-in [administrative clear](#administrative-clear-opt-in) lowers it. The plugin classifies tool calls for the monitor and rechecks the final command, URL or path at OpenCode's permission step.

> [!WARNING]
> This is a partial port. OpenCode 2 has no administrator-locked plugin seat and no managed gate, so a session without the plugin runs unguarded. OpenCode 2 also runs its tools unsandboxed, so the monitor refuses its sessions unless the plugin's `sandboxed` option is set for an OS-sandboxed install. Read [its README](shims/opencode/README.md) for the seat recipe and what it does not cover.

## Packaging

[`packaging/`](packaging) installs `barmkin monitor` as a root-managed service and seats the Claude Code shim and gate under the full lock.

| | Debian, Ubuntu: `packaging/install.sh` | NixOS: `packaging/nixos/module.nix` |
|---|---|---|
| Service user | system user `barmkin`, group `barmkin-clients`, no login | the same, uid `services.barmkin.uid` (default 917) |
| Monitor unit | [`packaging/systemd/barmkin-monitor.service`](packaging/systemd/barmkin-monitor.service) | the same unit |
| Binary | `/usr/local/bin/barmkin`, built static | the Nix store |
| Shim marketplace | `/opt/barmkin/plugins/claude-code` | the Nix store |
| Managed settings | `/etc/claude-code/managed-settings.json`, root's, `0644` | the same |

The unit runs as `barmkin:barmkin-clients`. systemd creates `/run/barmkin` (`0750`, holding `monitor.sock`) and `/var/lib/barmkin` (`0700`, holding the journal). `Restart=always` brings the monitor back after a crash, and every known lineage then returns tainted by `monitor_restart`. The unit drops every capability, keeps the file system read-only outside those two directories, allows only Unix sockets and filters system calls. The installed managed settings pin the gate to the `barmkin` uid.

**Debian and Ubuntu:**

```bash
sudo apt-get install -y bubblewrap socat
CGO_ENABLED=0 go build -o barmkin .
sudo packaging/install.sh install --client "$USER"   # log in again to take the group
sudo packaging/install.sh uninstall
```

`make managed-install` and `make managed-uninstall` do the same without `--client`. `install --admin-socket` also installs the opt-in [administrative socket](#administrative-clear-opt-in), and `install` without it removes the socket. `install` is idempotent. It restarts the monitor cleanly when the binary or unit changes, and it refuses to replace managed settings it did not write. `uninstall` removes everything `install` created.

**NixOS:**

```nix
imports = [ /path/to/barmkin/packaging/nixos/module.nix ];
services.barmkin = { enable = true; clients = [ "alice" ]; };
```

Then start `claude` as a member of `barmkin-clients`. `/barmkin-status` shows the legs and the monitor's state. Stop the monitor, or turn the shim off in the managed settings, to see every tool call denied.

## Development

| Command | What it runs |
|---------|--------------|
| `go test ./...` | Go tests, including every rule example, the gate against a real monitor, the shim's monitor client against a real monitor (Node 22.18+) and the gate lab fixture |
| `make shim-test` | `claude plugin validate --strict` and `claude plugin test` on the Claude Code shim (`npm ci` in `plugins/claude-code` installs the pinned Claude Code 2.1.289) |
| `make e2e` | End-to-end trust tests in `plugins/claude-code/e2e`: a real monitor, the shim's hooks module and the real gate (Node 22.18+) |
| `cd shims/opencode && bun test` | The OpenCode 2.x shim on Bun 1.4.2; set `BARMKIN_TEST_BIN` to a built `barmkin` to include a real monitor |
| `make claude-gate-demo` | [`scripts/claude-gate-demo.sh`](scripts/claude-gate-demo.sh): the gate and a real monitor with a curl-driven stand-in shim |
| `make claude-lock-lab` | [`scripts/claude-lock-lab.sh`](scripts/claude-lock-lab.sh): about forty real `claude -p` sessions under the full lock in bubblewrap (exits 77 if a prerequisite is missing) |
| `make packaging-test-ubuntu` | `packaging/install.sh` on Ubuntu 24.04 and 22.04 in privileged systemd containers (Docker) |
| `make packaging-test-nixos` | The NixOS module in a VM (KVM) |

CI runs `go vet`, `gofmt` on changed files, `go test`, the Claude Code shim, the OpenCode shim, the Ubuntu 24.04 packaging test, the e2e suite and gitleaks.

## Why the name?

A barmkin is a Scottish defensive wall around a tower house. My friend Sam, who is very Scottish, tells me his ancestors built these to keep my ancestors out. I'm choosing to read that as a compliment about our taste in architecture, our shared desire to try deep-fried battered Mars bars, and our mutual appreciation of Buckfast.

Had this been a network service, it would have listened on port 1707. Sam will know why. I do like Sam.
