# Barmkin

Regex guardrail for AI coding agents. Each tool call goes through `barmkin eval` before executing. If a rule matches, the command is blocked. Otherwise it passes silently.

Runs as a subprocess per invocation. Config is a YAML file of regex rules.

## Scope

Barmkin matches the strings in a tool call: shell commands, plus the target path and written payload (`content`, `new_string`, ...) of file-mutating tools such as Write and Edit. Search patterns and queries of read-only tools (Read, Grep, Glob, WebSearch, and any `*Search` action) are never scanned, and path-only rules (`target: "path"`, e.g. `.env` or `~/.ssh/id_rsa`) match only a file tool's target path, never its payload. It does not read files from disk or inspect command output. If you need semantic evaluation of what an agent writes or retrieves, use sondera, which adds Cedar policies and LLM classification on top.

An optional, off-by-default dynamic layer (`dynamic:` in rules.yaml) can ask a hosted classifier yes/no hazard questions about gated shell commands. It can only tighten a verdict to escalate or deny, never allow. See [demo/README.md](demo/README.md).

## Why the name?

A barmkin is a Scottish defensive wall around a tower house. My friend Sam, who is very Scottish, tells me his ancestors built these to keep my ancestors out. I'm choosing to read that as a compliment about our taste in architecture, our shared desire to try deep-fried battered Mars bars, and our mutual appreciation of Buckfast.

Had this been a network service, it would have listened on port 1707. Sam will know why. I do like Sam.

## Install

```bash
go build -o barmkin .
sudo ./install.sh
```

This puts the binary in `~/.local/bin/`, the config in `/etc/barmkin/rules.yaml`, and registers hooks for Claude Code, opencode, and GitHub Copilot CLI. Pass `claude`, `opencode`, or `copilot-cli` to install for one harness only.

### Claude Code

A PreToolUse hook in `~/.claude/settings.json` runs `barmkin eval` on every `Bash`, `Write`, `Edit`, `MultiEdit`, and `NotebookEdit` call. Exit 2 blocks and stderr goes to the LLM.

### opencode

The plugin at `plugins/barmkin.ts` spawns `barmkin eval` on every `tool.execute.before` event. Installed to `~/.config/opencode/plugins/`.

### GitHub Copilot CLI

A preToolUse hook in `/etc/github-copilot/policy.d/barmkin.json` runs `/usr/local/bin/barmkin eval`. Barmkin always answers with explicit `permissionDecision` JSON. The registration schema has not yet been verified against a real Copilot CLI install; see [demo/README.md](demo/README.md).

## Commands

```
barmkin eval       stdin in, exit 0 or exit 2
barmkin test       run deny/allow test vectors
barmkin validate   check config, rules, examples
barmkin stats      aggregate from log file
barmkin version
```

## Rules

49 rules across 10 categories. Every rule has an `example` field that `go test` verifies automatically. Adding a rule with an example adds a test.

| Category | Rules |
|----------|-------|
| Destructive | rm-rf, chmod 777, fork bomb, shutdown, kill -9 -1, shred, mkfs, dd, wipefs, redirect to device |
| Git | reset --hard, push --force, clean -fd, filter-branch |
| Database | TRUNCATE TABLE, DROP TABLE, DROP DATABASE, DELETE without WHERE |
| Exfiltration | curl\|bash, wget\|bash, scp ssh keys, curl upload, tar\|ssh, nc pipe, rsync remote |
| Supply chain | npm git+ install, pip untrusted URL |
| Obfuscation | base64+exec, eval hex |
| Sensitive paths | Write/Edit targets: SSH keys, authorized_keys, .env, credentials files |
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
