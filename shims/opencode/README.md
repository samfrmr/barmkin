# 🏰 barmkin-opencode 🏰

barmkin's shim for **OpenCode 2.x**: a plugin, `barmkin-opencode`, that guards each OpenCode session as a client of [`barmkin monitor`](../../README.md#monitor-core-barmkin-monitor). It is a port of barmkin-mod's OpenCode plugin (barmkin-mod `opencode/`), in which the monitor holds every session's taint. It redacts secrets, screens untrusted content, and refuses outward-effect tools while the session is tainted.

> [!WARNING]
> **This is a partial port, not equivalent to barmkin-mod for Claude Code. OpenCode 2 has no administrator-locked plugin seat.** Read [What this is not](#what-this-is-not) before relying on it.

## What this is not

barmkin-opencode ships as a **user-owned seat, not administrator-enforced**. OpenCode 2.x has no machine-level or managed plugin seat: no `/etc/opencode`, no MDM path, no root-owned file. "Managed" on 2.x means policy only, and OpenCode's own threat model protects policy, not third-party plugins. A repository's `opencode.json` can unload this guard with one line unless project config is disabled or the guard is seated through `OPENCODE_CONFIG_CONTENT`. There is no managed gate, as there is for Claude Code: a session without the guard runs its tools unguarded.

Outward-effect tools (shell, web fetch, file writes) are refused while the session is tainted, **provided this guard is loaded**. The refusal is re-checked at OpenCode's permission step against the final command, URL or path, so another plugin cannot rewrite its way past it. It does **not** cover MCP tool arguments, Code Mode `fetch`, or command-template shell. **OpenCode 2 has no administrator-locked plugin seat:** a repository's `opencode.json` can unload this guard unless project config is disabled or the guard is seated through `OPENCODE_CONFIG_CONTENT`. **No posture line means no guard.**

OpenCode 2 also has no sandbox for its tools, so they can reach the monitor's socket. The monitor refuses a session whose tools run outside a sandbox, so **with OpenCode as it ships, the monitor refuses every session and every guarded call is denied.** Set the `sandboxed` option only when OpenCode itself runs inside an OS sandbox whose tools cannot reach the monitor socket (see [The monitor](#the-monitor)).

### Not covered

These four are named so nobody assumes them:

1. **Evidence stays in stored transcripts.** Redaction rewrites what the model reads and what tool results store, but a tool call's `input` is stored raw, every shell command's full output is spilled raw to disk for 7 days before any hook runs, and background-shell and other synthetic messages reach the transcript raw. Secrets are not absent from the stored transcript.
2. **MCP tool descriptions are only as clean as the neutraliser.** The description neutraliser (`src/mcp-guard.ts`) rewrites instruction-like text and strips hidden characters in MCP tool descriptions, input schemas and server instructions. It is a heuristic: text it does not recognise as instructions reaches the model. If it fails to install, the posture line names MCP tool descriptions as not covered.
3. **No protection when the guard is absent.** There is no `--pure` flag on 2.x, but nothing locks the guard in either. It is gone, silently, if a repository config removes it (`"plugins": ["-barmkin-opencode"]`), if the process runs without the seat's environment (a different `OPENCODE_CONFIG_CONTENT`, `--standalone` or `--server` against another environment, `opencode plugin remove`), or if its `setup` throws (the plugin is dropped with one WARN line and the session runs unguarded). A transform that throws later disables every hook of the plugin mid-session. Removal by config leaves no log line and no failed entry.
4. **The repo-plugin surround.** Code in a cloned repository that runs beside the guard (repository plugins, `.opencode/` plugins in the repository or any ancestor directory, repository commands and skills) is outside what this guard governs. Only the plugin allowlist and project config off keep it from loading, and both are operator choices, not defaults.

### Documented limitations

- **Human-origin clearing.** OpenCode 2's `session.prompt` hook carries no origin and synthetic user-role messages exist, so the guard cannot tell a person's message from an injected one. The taint is therefore sticky: nothing clears it, not a prompt, a command or a compaction, and there is no clear command. Only a new session starts clean.
- **Command-template shell.** `` !`cmd` `` in a command template runs with no tool hook, no shell hook and no permission check. It cannot be mediated. Disabling project config removes repository command templates.
- **Shell layer.** OpenCode 2 does not give plugins the session identity of a shell call, so a session taint can restrict shell commands in unrelated sessions on the same instance, and a shell not launched through a tool call bypasses the shell gate entirely. (`shell.create.before` carries no session in its inputs.) The shell layer checks a command against every session with a shell tool call in flight, and denies it only when every one of them would deny it. Otherwise it leaves the command to the permission step, which rechecks it with the call's own session, so a tainted session's command is still refused there.

## The monitor

The guard keeps no taint of its own. Every OpenCode session registers with the monitor as a session of its **root lineage**: a subagent's session registers under the top-level session it descends from, so they share one pair of legs (untrusted and sensitive). The monitor decides every call on those legs, and the guard writes the deny text.

- **Registration.** A session registers at its first model request, while its history holds only the person's prompt. Only a brand-new top-level session registers as fresh: no parent, not a fork, nothing in its history but the person's own messages. Any other session the monitor has never seen starts with its untrusted leg raised by `unknown_session`, because its history is not known to be clean. A session the monitor already knows keeps its legs.
- **Restarts keep the taint.** The legs live in the monitor's journal, keyed by the root session, so an OpenCode restart finds them where it left them. After a monitor crash or `kill -9`, every lineage comes back tainted by `monitor_restart`. A monitor that lost its journal starts every session with history tainted.
- **Legs only rise.** A fetched page, an MCP result, a subagent's result, a Code Mode result or a file read from outside the project goes to the monitor's screen as redacted windows. A skill load raises the untrusted leg before it runs, and loads are decided one at a time. A credential path in a call, or a credential-shaped value in a result, raises the sensitive leg. With both legs up every egress class is denied (the Rule of Two).
- **The screen.** The monitor core has no classifier yet, so its screen raises the untrusted leg for the content's source and answers `unavailable`. The guard then withholds every piece of untrusted content.
- **MCP findings stay with the sessions that use the server.** Hidden text the MCP guard strips from a server's descriptions, schemas or instructions is a finding about that server, made before any session exists. It is kept under a hash of the server's configuration. It raises the untrusted leg only of a session whose model request lists that server's tools or instructions, or that calls one of its tools. Other sessions on the same instance stay clean, and a server whose configuration changes is judged afresh.
- **Failure denies.** Every request has a 1-second deadline. When the monitor is unreachable, times out, answers with an error or a malformed reply, or speaks another protocol version, every tool call is denied (a read as well as a shell command), untrusted content is withheld, and a result whose leg could not be recorded is withheld. A model request whose hidden text or MCP finding could not be recorded is not sent.
- **Posture.** The guard reports how OpenCode runs its tools. OpenCode 2 has no tool sandbox, so it reports an unsandboxed posture unless the `sandboxed` option says otherwise, and the monitor refuses an unsandboxed session (`posture_refused`). Only set `sandboxed` when OpenCode itself runs inside an OS sandbox whose tools cannot reach the monitor socket. Neither the guard nor the monitor can check that sandbox: `sandboxed` is the operator's claim, and the operator must prove it.

Locally, without the monitor, the guard keeps secret redaction and the invisible-text scrub, prompt redaction, the MCP description neutraliser and server allowlist, the skill-listing neutraliser, the posture line and the status channel to the TUI half (`tui.tsx`, `/barmkin-status`).

| Environment variable | Description |
|---|---|
| `BARMKIN_MONITOR_SOCKET` | the monitor's Unix socket (required) |

| Plugin option | Description |
|---|---|
| `sandboxed` | `true` only when OpenCode runs inside an OS sandbox whose tools cannot reach the monitor socket; otherwise the monitor refuses every session |
| `mcp_server_allowlist` | MCP server names, an array or a comma-separated string; empty allows every server |
| `debug` | log the guard's own failures to stderr |

### Posture line

The plugin prints one line at startup naming the seat it found. Its wording is fixed:

```
🏰 barmkin-opencode 0.1.0 (core <git-sha>) · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: <per-seat gaps>
```

Conditional lines follow it, one per condition: a seat a repository can unload, plugins loaded beside the guard, an unreadable plugin inventory, a monitor socket that is not set or a monitor that did not answer its health check, and an unsandboxed posture. No line means the guard is not running.

## The seat recipe

The supported deployment has three parts. All three were verified together against a hostile repository (a repository that shipped its own plugins, `-barmkin-opencode` and `-*` removals, and a counter-policy): only the guard loaded and the outward command was refused.

1. **Seat the guard through `OPENCODE_CONFIG_CONTENT`.** It is the last third-party plugin in OpenCode's chain, and a repository's config cannot remove it. For the default background service, store it in the service environment (`opencode service set env OPENCODE_CONFIG_CONTENT '<json>'`); for `--standalone`, set it in the launcher's environment.
2. **Put a plugin allowlist in your user-global `opencode.json`.** Under `experimental.policies`, deny `plugin:*` and allow only `barmkin-opencode`. Then a repository cannot add its own plugins, and a repository policy cannot override yours. `experimental.policies` is an experimental key; recheck it on every release.
3. **Set `OPENCODE_DISABLE_PROJECT_CONFIG=1`** in the same environment. This drops repository and ancestor-directory config, including `AGENTS.md`-style config, commands and skills.

The inline-config seat and project config off each keep the guard loaded against a repository's removal entries on their own; the allowlist does not (a repository `-barmkin-opencode` still removes a guard seated in a file). Only the combination also stops repository plugins from running beside the guard. All three are **user-owned**: an environment variable or the user's `service.json`, plus the user's config file. The user, and any process running as the user, can change them.

A guard seated any other way (global `plugins/` directory, global `opencode.json`, `OPENCODE_CONFIG`) can be unloaded by one line in a cloned repository, and a later repository plugin can re-insert what the guard redacted.

## Install

1. Install OpenCode at an exact tested version (see [Tested range](#tested-range)). Do not run on an untested release.
2. Run `barmkin monitor` (see the [packaging](../../README.md#packaging-the-managed-monitor-and-claude-code-seat)) and make the OpenCode user a member of its client group.
3. Build the plugin (see [Build the bundle](RELEASE-CHECKLIST.md#build-the-bundle)) into a directory named `barmkin-opencode` containing `server.js` (a configured plugin must be a directory; a bare file path in `plugins[]` is rejected). Keep it outside OpenCode's auto-discovered `plugins/` directories so the seat, not discovery, loads it.
4. Seat it: set `OPENCODE_CONFIG_CONTENT='{"plugins":[{"package":"/absolute/path/to/barmkin-opencode"}]}'` and `BARMKIN_MONITOR_SOCKET=/run/barmkin/monitor.sock` for the service or the launcher. Add `"options":{"sandboxed":true}` only when you have put OpenCode inside an OS sandbox and checked that its tools cannot reach the socket.
5. Add the allowlist to the user-global `opencode.json` (deny `plugin:*`, allow `plugin:barmkin-opencode`).
6. Set `OPENCODE_DISABLE_PROJECT_CONFIG=1` in the same environment.
7. Start OpenCode and confirm the posture line appears. If it does not, the guard is not running.

barmkin-mod's optional `opencode-canary/` plugin, which names the guard's state in the TUI when the guard's own setup failed, is not part of this port.

`plugins/barmkin.ts` at the repository root is the legacy `barmkin eval` plugin. It has the OpenCode 1.x plugin shape and does not load on 2.x.

## Tested range

- **Starts at OpenCode 2.0.28** (the Linux x64 binary, embedded Bun 1.4.2). Nothing earlier is supported, and 1.x is not supported at all: a 1.x plugin does not load on 2.x.
- OpenCode ships about seven stable releases a week and `experimental.policies` is still experimental. **Pin an exact version** and follow [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md) on every upgrade.
- Linux only so far. The lab used a scripted model, not a real one.

## Tests

The suite lives in `tests/` as `*.spec.ts` (so `claude plugin test` does not pick up these Bun-only files) and runs on Bun 1.4.2:

```
cd shims/opencode && bun test
```

- The T-SEAT contract suite checks, against a model of the 2.x host built from the verified behaviour: removal by `-id` and `-x.*`, the plugin allowlist, the inline-config seat, `permission.evaluate`-throw finality, tool-rename detection and shell-layer rewrite detection. It also checks that this README keeps its non-equivalence wording.
- The monitor suites run the real guard in that host model against the Claude Code shim's in-memory monitor, served on a real Unix socket. They cover registration in the root lineage, failure denial, two sessions on one instance where only the one that uses a poisoned MCP server is tainted, OpenCode and monitor restarts, and the shell layer when the shell's session is ambiguous.
- `tests/monitor-socket.spec.ts` runs the guard against a real `barmkin monitor` through Bun's `fetch` with `unix`, and kills and restarts it. It needs the binary: build it at the repository root (`go build -o /tmp/barmkin .`), then run `BARMKIN_TEST_BIN=/tmp/barmkin bun test` here.

None of them runs the OpenCode binary; the per-release checklist does. A contract test is skipped when its module or the barmkin binary is missing. Set `BARMKIN_CONTRACT_STRICT=1` (CI, integration and release runs) to make a missing one fail instead. `npm ci && npm run typecheck` type-checks the shim and its tests.
