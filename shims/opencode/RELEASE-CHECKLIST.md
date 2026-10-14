# Release checklist: barmkin-opencode on OpenCode 2.x

OpenCode 2.x ships about seven stable releases a week, and `experimental.policies` is still experimental. The T-SEAT suite in `tests/` runs against a model of the host, so only a run against the real binary shows that a new release still behaves the way the model says. Do this for **every** OpenCode version the port claims to support.

## 1. Pin the exact version

- [ ] Name one exact OpenCode version (for example `2.0.28`), never a range or `latest`. Record it in the release notes and in the README's tested range.
- [ ] Install exactly that `@opencode/cli` build, and note the Bun version it embeds (`strings <binary> | grep 'Bun v'`). The port targets that Bun, currently 1.4.2, which CI pins for the suite.
- [ ] The tested range starts at 2.0.28. Do not claim anything earlier, and do not claim a version that has not passed section 2.
- [ ] If the version is new, diff the plugin-relevant paths against the last tested tag (plugin runtime, supervisor, hook runner, config discovery and precedence, permission, tool, shell, policy). A non-additive change is a stop: re-scout before continuing.

### Build the bundle

The guard ships as one file with no runtime dependency: the shared library (`src/lib.ts`, from `plugins/claude-code/barmkin-shim/hooks/lib`), `shims/common/proto.ts` and `shims/opencode/src` are inlined, and nothing is imported from `@opencode/*`. Build it from the repository root with the pinned Bun:

```
bun build shims/opencode/server.ts --target bun \
  --define BARMKIN_CORE_SHA="\"$(git rev-parse --short HEAD)\"" \
  --outfile barmkin-opencode/server.js
```

- [ ] The command succeeds and writes `barmkin-opencode/server.js` (about 120 KB). `BARMKIN_CORE_SHA` is the `core <git-sha>` in the posture line; without the `--define` the line says `core unbuilt`.
- [ ] `grep -cE '^import |require\(' barmkin-opencode/server.js` prints `0`: no external import survived.
- [ ] To ship the TUI half, put `shims/opencode/tui.tsx`, `shims/opencode/src/status-rpc.ts` and `shims/opencode/src/tui-view.ts` in the same directory (the last two under `src/`). OpenCode loads `tui.tsx` only from beside the server entry, and the server half works without it.
- [ ] No bypass flag or environment override exists in the bundle: the only plugin options are `sandboxed`, `mcp_server_allowlist` and `debug` (logging only), and the only environment variable is `BARMKIN_MONITOR_SOCKET`.

## 2. Per-release subset re-run

Run against the real binary with an isolated HOME and every XDG directory inside a scratch directory, `--standalone`, a scripted model, and `< /dev/null` for headless runs. Never use the shared background service. The check ids are from the 2.x re-scout.

Seat and removal (the T-SEAT claims):

- [ ] **V1** Seven seats load in the documented order, with `OPENCODE_CONFIG_CONTENT` last.
- [ ] **V10, V12, V13** A repo `"-barmkin-opencode"` and `"-<x>.*"` unload a file-seated guard; they do not unload the `OPENCODE_CONFIG_CONTENT` guard.
- [ ] **V14** `OPENCODE_DISABLE_PROJECT_CONFIG=1` keeps every file seat against repo removals.
- [ ] **V15, V16** The user-global allowlist blocks repo and global-dir plugins and ignores a repo counter-policy; a repo `-id` still removes an allowlisted guard from a file seat. Confirm the exact `experimental.policies` key names and the `plugin:<id>` resource spelling on this version.
- [ ] **V38** The full recipe against a hostile repo: only the guard loads, the outward command is refused.
- [ ] **V41** Removal still leaves no log line and no failed entry (the posture line is the only signal).

Deny and rewrite finality:

- [ ] **V2** A throw in `execute.before` refuses the tool; later before-hooks do not run.
- [ ] **V6, V7** `effect = "deny"` at `permission.evaluate` is still overridable by a later plugin; a throw is still final.
- [ ] **V8** A later plugin renaming `read` to `shell` is stopped at evaluate.
- [ ] **V9** A command rewritten in `shell.create.before` is stopped at evaluate, and evaluate sees the rewritten command.
- [ ] **V17, V19** A setup throw still drops the plugin with one WARN; a transform throw still disables the plugin mid-session. (The guard must never throw in a transform.)

Guard-specific:

- [ ] **V20, V21, V28** Redaction reaches the model on the completed and error paths and at `session.context` and `session.title`.
- [ ] **V23** The MCP description neutraliser, if shipped, still reaches both direct and Code Mode tool descriptions.
- [ ] **V24, V25, V32** The not-covered paths (MCP arguments at evaluate, Code Mode `fetch`, command-template shell) still behave as the README says. A path that becomes covered, or one that newly leaks, is a README change.
- [ ] **V34, V35** Toast and the three slots still render; the native "plugin failed" indicator still appears.
- [ ] The shell-layer limitation in the README still holds: `shell.create.before` has no session in its inputs.

The monitor (a real `barmkin monitor`, the guard seated as above with `sandboxed` and `BARMKIN_MONITOR_SOCKET`):

- [ ] A new session registers fresh at its first model request, and an outward command in it runs.
- [ ] A fetched page is withheld and taints the session; an outward command after it is refused, and still refused when the session is resumed in a new OpenCode process.
- [ ] After `kill -9` and a restart of the monitor, a clean session comes back tainted by `monitor_restart` and its outward command is refused.
- [ ] With the monitor stopped, every tool call is refused. Without `sandboxed`, the monitor refuses the session and every tool call is refused with the posture text.
- [ ] A session that calls a tool of an MCP server whose description hides text is tainted by `mcp`; a session on the same instance that never lists or calls that server is not.

Suites:

- [ ] `cd shims/opencode && BARMKIN_CONTRACT_STRICT=1 BARMKIN_TEST_BIN=<barmkin> bun test` on the pinned Bun: every contract module present and the real-monitor suite run, nothing skipped (the suite in `tests/`, which `bunfig.toml` points at).
- [ ] `npm run typecheck` is clean, and the Claude Code shim's suite (`plugins/claude-code`, `npm test`), which covers the shared library, is green.

## 3. Posture-line snapshot gate

- [ ] Start the guard in the supported seat on the pinned version and capture the startup posture line verbatim.
- [ ] Compare it with the committed snapshot. The prefix is fixed text:
      `🏰 barmkin-opencode 0.1.0 (core <git-sha>) · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: <per-seat gaps>`
- [ ] Any change to the fixed wording needs captain approval. Only `<git-sha>` and `<per-seat gaps>` may vary between releases.
- [ ] Repeat in each seat the release claims (inline-config seat with and without the allowlist and project config off) and confirm the `not covered:` list names the gaps for that seat.
- [ ] Remove the seat and start again: confirm **no** posture line appears.
- [ ] `shims/opencode/README.md` still carries the re-scout section 2.2 wording verbatim, including "No posture line means no guard" and the unsandboxed-refusal paragraph (checked by hand; no test covers it).

## 4. Sign-off

- [ ] README tested range updated to the pinned version.
- [ ] The release notes copy the four NOT-covered items and the sentence "OpenCode 2 has no administrator-locked plugin seat".
- [ ] Anything that failed above is either fixed or written into the README as a limitation before release.
