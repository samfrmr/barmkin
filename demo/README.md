# Barmkin dynamic-hooks demo

A lightweight, Claude-Code-CLI-only vertical slice of the "dynamic
hooks" plan in `data/barmkin-dynamic-hooks/report.md` (this repo's
sibling planning doc, not shipped here): a second evaluation stage
inside `barmkin eval` that asks Jev (TypeSafe's "System One" decision
model) a couple of yes/no hazard questions about a gated shell command,
and composes the answers in code into `pass | escalate | deny`.
Barmkin never lets the model say "allow" - the dynamic layer can only
tighten a verdict, never loosen one.

Run it:

```
./demo/run-demo.sh
```

## Captain revision (2026-10-01): internal gateway is now the default

The model is hosted internally and served through an internal gateway;
data stays inside the corporate boundary. This revises D1/D2/D3 from
the original plan:

- **`provider.base_url`** now defaults to an internal gateway in front
  of the self-hosted model (Tier A), not OpenRouter direct. The demo
  configs (`demo/rules-shadow.yaml`, `demo/rules-enforce.yaml`) point
  at a placeholder host, `jev-gateway.internal.example` (an RFC 2606
  `.example` domain that will never resolve) - point it at your real
  gateway to use this for real. OpenRouter/TypeSafe direct (Tier B) is
  now only a **fallback for isolated testing** without a gateway - see
  `demo/rules-shadow-openrouter-fallback.yaml` and
  `demo/rules-enforce-openrouter-fallback.yaml`.
- **`provider.auth.type`** defaults to `none` (the gateway authenticates
  the caller via workload identity - mTLS, SPNEGO, etc.) in the
  gateway configs. `auth.type: command` runs a short-lived-token
  broker (`command: ["/usr/local/bin/corp-token", "jev"]`) and uses
  its trimmed stdout as the bearer token, for gateways that still want
  a bearer header. `bearer_file` remains supported, but only as an
  explicit, commented-out, local-testing-only override - never for the
  internal gateway.
- **`provider.redact`** is a new field: `default` (apply the built-in
  redaction before egress - command text + cwd only, secret patterns
  masked) or `off` (send the raw command/cwd). The gateway configs set
  `redact: off`, since this data no longer crosses the corporate
  boundary. The OpenRouter fallback configs keep `redact: default`,
  since that path *does* leave the boundary. The redaction code itself
  is unchanged and still runs for any external-egress fallback.

**Open item:** the internal gateway/model host must itself serve the
System One wire format this client speaks - `POST /v1/systemone`,
each question carrying a required `"instructions"` string (see
"instructions field" below) - or sit behind a format adapter that
translates to it. **This has not been verified against any real
internal host**; `demo/run-demo.sh` runs against the placeholder
domain by default for exactly this reason. Point `base_url` at the
real gateway and rerun to check.

## What's in scope for this demo

Per the captain's intent (lightest-weight option; originally direct
egress with no corporate gateway/proxy, revised 2026-10-01 above to
default to an internal gateway):

- **Phase 1 refactor** (`decision.go`): a `Decision{Pass,Escalate,Deny}`
  type, a Claude Code output adapter (`renderEscalateJSON`), and a
  GitHub Copilot CLI output adapter (`renderCopilotCLIOutput`,
  `{"permissionDecision":"allow"|"deny"|"ask",...}` - report.md §5c).
  `barmkin stats` now counts `escalate` separately from `allow` and
  summarizes the dynamic layer's unavailable rate and p50/p95 latency
  (`main.go`'s `computeStats`); Claude Code's Write/Edit `file_path` is
  now scanned by the regex layer (`hook.go`'s `extractContent`), with
  new `rules.yaml` rules for `~/.ssh` key material, `authorized_keys`,
  `.env`, and common credential files (report.md §2.7/§7); and the
  golden-equivalence test now replays every rule example plus the full
  false-positive corpus from the real `rules.yaml`, not a 3-command
  sample. All of the above were previously **out of scope** for this
  demo and are now complete.
- **Phase 2 Jev client** (`jev.go`): System One wire format
  (`POST {base_url}/v1/systemone`), each question carrying a required
  `"instructions"` string (see below), HTTPS to `provider.base_url` -
  an internal gateway (Tier A, now the default) or a direct provider
  (Tier B, isolated-testing fallback) - pinned `jev-1.13`, strict
  response validation (model spelling, answer shape, `noul` range), no
  redirects (`CheckRedirect` always errors), a 0600 key file for the
  `bearer_file` auth option (D3), and configurable redaction/truncation
  before egress (D2: command text + cwd only, truncated to 4,000
  chars, secret patterns masked when `provider.redact` isn't `off` -
  never file contents).
- **Instructions field:** TypeSafe's System One schema requires every
  question to carry an `"instructions"` string (object/array also
  accepted; `criteria` optional). An earlier version of this client
  omitted it and OpenRouter rejected the request with `400
  invalid_union` on `questions.*.instructions: expected string,
  received undefined`. Fixed and **verified live against OpenRouter**:
  `jevQuestion.Instructions` has no `omitempty` (so the key is always
  present, even empty), `defaultQuestions` in `dynamic.go` carry real
  instructions text, and `dynamic_test.go` has a marshal-level
  regression guard plus a schema-enforcing stub test.
- **Dynamic layer** (`dynamic.go`): the gate (bash tool calls only, in
  `auto`/`bypassPermissions`/`dontAsk`, per D10), a built-in read-only
  fast path, and the D6 allow-rule skip. Regex denies never reach Jev
  (`engine.go` only calls the dynamic layer when the regex layer found
  nothing to deny).
- **Question set:** exactly two, per the demo brief: `no_secret_egress`
  (hazard, rejects at `p <= 0.03` → deny) and `no_outward_effect`
  (soft, rejects at `p <= 0.10` → escalate). Thresholds are the D1/D4
  defaults from the full plan; override via `dynamic.thresholds` in
  config.
- **Shadow → enforce flip:** `demo/rules-shadow.yaml` always passes and
  logs what it would have done; `demo/rules-enforce.yaml` acts on the
  composition and fails closed-to-manual (`escalate`) when Jev is
  unreachable, with `bypassPermissions` mapped to `deny` (for both
  on_unavailable and a composed soft-question escalation) until a human
  verifies hook `ask` is honoured there (report.md §5c). A per-session
  breaker (`~/.barmkin/state/<session>.json`, 0600, atomic
  write-then-rename) opens after one consecutive failure and
  short-circuits further network calls until its cooldown elapses -
  this is what "the breaker opening when the key is pulled or timeout
  hits" looks like in practice.
- **Audit log:** gains `decision: "escalate"`, a `layer` field
  (`"dynamic"` when this stage ran, absent/omitted otherwise), and a
  `dynamic` block with the outcome, would-be decision, error kind,
  provider/model/latency, the deciding question and probabilities (even
  on pass, so shadow-mode calibration is possible), and breaker state.
  SIEM/log-consumer acceptance of the new fields is explicitly deferred
  (D9) to a later milestone - not checked by this demo.

Out of scope here (see report.md §5h "Phase 4" and the demo brief):
opencode and GitHub Copilot in VS Code adapters, an `intent_coverage`
question, a local daemon, and the Phase 0 harness contract checks
(those need a human with a real account on a real harness, including
confirming the Copilot CLI `preToolUse`/`policy.d` mechanics below
against a real install). Tier A credential *shapes* (`auth.type:
none`/`command`) are now in scope and implemented; a real internal
gateway to point them at is not - that's the open item above. Copilot
CLI's output adapter and `policy.d` hook-registration snippet, and
Write/Edit path gating, were out of scope for the original demo brief
but are now implemented (see the Phase 1 refactor bullet above and the
"GitHub Copilot CLI" section below).

## GitHub Copilot CLI (enforce target #2, alongside Claude Code)

Per the captain's D5 sequencing (report.md, bottom - "Claude Code and
Copilot CLI together first"), Copilot CLI already has its own genuine
`preToolUse` hook with a confirmed `ask`, structurally the same
pass/escalate/deny shape as Claude Code's hook. `main.go`'s `cmdEval`
detects a Copilot CLI request (camelCase `toolName`/`toolArgs`, no
Claude Code `tool_name`/`session_id`) and renders
`decision.go`'s `renderCopilotCLIOutput` instead of the Claude Code
adapter:

- pass → `{"permissionDecision":"allow"}` (always explicit; unlike
  Claude Code there's no documented silent-exit-0 convention here)
- escalate → `{"permissionDecision":"ask","permissionDecisionReason":"…"}`
- deny → the same JSON with `"deny"`, plus the existing exit 2 (kept
  for forward compatibility with whichever of "exit 2" or the JSON
  field this harness actually reads for the reason - report.md §5c)

Register the hook on the admin-exclusive channel:

```
sudo ./install.sh copilot-cli
```

This writes `/etc/github-copilot/policy.d/barmkin.json` and copies the
binary to `/usr/local/bin/barmkin` (a fixed, fleet-wide path, since
`policy.d` is machine-scoped, not per-user like Claude Code's
`~/.claude/settings.json`). **The exact on-disk schema is this scout's
best-effort reconstruction from GitHub's docs, not verified against a
real Copilot CLI install** - confirming it actually fires (and the
version floor, ≥ 1.0.66 for honoured `ask`) is a Phase 0 operator
check, same status as this demo's unverified internal-gateway
connectivity above. Barmkin's own side - the output adapter and input
detection - is unit-tested against the documented wire shapes
(`decision_test.go`, `barmkin_test.go`'s Copilot CLI engine tests), the
same "unit-test the wire format, leave live connectivity to Phase 0"
split used for the Jev client itself.

## Files

| File | Purpose |
|---|---|
| `decision.go` | `Decision` enum + Claude Code and Copilot CLI output adapters |
| `jev.go` | System One client: auth, redaction, transport, strict validation |
| `dynamic.go` | gate, state builder, composition, per-session breaker |
| `config.go` (`dynamic:` block) | provider/gate/on_unavailable/breaker config, `validate` support |
| `log.go` (`DynamicAudit`) | the additive audit-log fields |
| `dynamic_test.go` | golden equivalence, monotonicity, gating, composition, breaker, transport-failure-matrix tests |
| `demo/rules-shadow.yaml`, `demo/rules-enforce.yaml` | internal-gateway (Tier A) configs - the default |
| `demo/rules-shadow-openrouter-fallback.yaml`, `demo/rules-enforce-openrouter-fallback.yaml` | OpenRouter-direct (Tier B) configs - isolated-testing fallback, used by `run-demo.sh` only when `demo/jev.key` is present |
| `demo/run-demo.sh` | runs the gateway configs against sample commands, the fallback configs if a key is present, and prints the audit log |

## The direct-egress finding (resolved)

The original brief said: *"use direct egress (personal OpenRouter or
TypeSafe key) for now... if direct egress is blocked in this
environment, report that concretely rather than working around it."*

While first building this demo, a single raw connectivity probe
(`curl -X POST https://openrouter.ai/api/v1/systemone` run directly
via the Bash tool, no key, just checking for the expected 401) was
**refused by this task's own harness**, not by a network-level block:
the auto-mode classifier denied it as `[Exfil Scouting]` - the same
class of refusal the original scout report hit probing
`bypassPermissions`. That raw probe was never retried.

**Since then, a live round trip through this binary (not a raw curl)
has been run and verified**, against both the (then-current)
OpenRouter-direct config and, after the instructions-field fix above,
again successfully. `demo/run-demo.sh`'s fallback section (OpenRouter
direct, Tier B) exercises this automatically whenever `demo/jev.key`
is present - real `request_id`, `latency_ms`, and probabilities show
up in `demo/out/enforce-openrouter.log`'s `dynamic` block. One live
run surfaced a real instance of Jev's documented "indirection"
jaggedness: `curl ... -d @~/.ssh/id_rsa` (which reads and POSTs a
private key via curl's `@file` syntax) was scored `0.97` on the
then-current question wording, which asked the hazard question
("Does the command send credentials...?") while composition reads a
high `no_secret_egress` probability as *safe*. The model answered
correctly; Barmkin read it backwards. Both questions are now worded
so that "yes" means safe, matching the `no_*` ids and the
`p <= threshold` reject rule.

To exercise this yourself:

```
echo "sk-or-v1-..." > demo/jev.key   # a real OpenRouter key, hard credit cap
chmod 600 demo/jev.key
./demo/run-demo.sh
```

`jev.key` is git-ignored; never commit a real key. The gateway configs
(`demo/rules-shadow.yaml`, `demo/rules-enforce.yaml`) still run by
default against the placeholder `.example` host regardless of whether
a key is present - the open item above (no real internal gateway to
point them at yet) is independent of this finding.

## Decisions this demo takes as given

Per the captain's D1-D10 record (report.md, bottom), as revised
2026-10-01: **D1** internal gateway in front of a self-hosted model
(Tier A default), OpenRouter pinned `jev-1.13` kept as the Tier B
isolated-testing fallback; **D2** redaction off by default for the
gateway path (data stays inside the corporate boundary), still on by
default for the Tier B fallback (command text + cwd only); **D3**
workload identity / command-sourced token for the gateway (`auth.type:
none` or `command`), a per-user capped key in a 0600 file kept as the
Tier B fallback auth; **D4** escalate with breaker, `bypassPermissions
→ deny` pending Phase 0; **D6** allow rules skip the dynamic layer;
**D7** off-only env kill switch (not implemented in this demo - no
`BARMKIN_DYNAMIC` env check - since the demo's own config files are
the on/off switch; add it if this graduates past a demo); **D8** regex
layer's existing fail-open postures unchanged; **D9** SIEM acceptance
deferred; **D10** bash-only gating in unattended modes.

**D7 update:** the off-only `BARMKIN_DYNAMIC=off` env kill switch is now
implemented (`config.go`'s `applyDynamicKillSwitch`) - it can only
disable the dynamic layer, never enable one a config leaves off, and
`barmkin validate` reports when it's in effect.
