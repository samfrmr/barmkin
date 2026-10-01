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

## What's in scope for this demo

Per the captain's intent (lightest-weight option, direct egress, no
corporate gateway/proxy):

- **Phase 1 refactor** (`decision.go`): a `Decision{Pass,Escalate,Deny}`
  type and a Claude Code output adapter (`renderEscalateJSON`). Stats
  changes, Write/Edit path-gating, and the golden corpus expansion are
  explicitly **out of scope** for this demo.
- **Phase 2 Jev client** (`jev.go`): System One wire format
  (`POST {base_url}/v1/systemone`), direct HTTPS egress to
  `provider.base_url` with no corporate proxy/gateway, pinned
  `jev-1.13`, strict response validation (model spelling, answer
  shape, `noul` range), no redirects (`CheckRedirect` always errors),
  a 0600 key file (D3), and redaction/truncation before egress (D2:
  command text + cwd only, truncated to 4,000 chars, secret patterns
  masked - never file contents).
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
  unreachable, with `bypassPermissions` mapped to `deny` until a human
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
opencode/Copilot/VS Code adapters, Write/Edit path gating, an
`intent_coverage` question, a local daemon, Tier A gateway, and the
Phase 0 harness contract checks (those need a human with a real
account on a real harness).

## Files

| File | Purpose |
|---|---|
| `decision.go` | `Decision` enum + Claude Code escalate-JSON output adapter |
| `jev.go` | System One client: auth, redaction, transport, strict validation |
| `dynamic.go` | gate, state builder, composition, per-session breaker |
| `config.go` (`dynamic:` block) | provider/gate/on_unavailable/breaker config, `validate` support |
| `log.go` (`DynamicAudit`) | the additive audit-log fields |
| `dynamic_test.go` | golden equivalence, monotonicity, gating, composition, breaker, transport-failure-matrix tests |
| `demo/rules-shadow.yaml`, `demo/rules-enforce.yaml` | the two demo configs |
| `demo/run-demo.sh` | runs both configs against sample commands and prints the audit log |

## The direct-egress finding

The brief said: *"use direct egress (personal OpenRouter or TypeSafe
key) for now... if direct egress is blocked in this environment,
report that concretely rather than working around it."*

While building this demo, a single connectivity probe
(`curl -X POST https://openrouter.ai/api/v1/systemone`, no key, just
checking for the expected 401) was **refused by this task's own
harness**, not by a network-level block: the auto-mode classifier
denied it as `[Exfil Scouting]`. This is the same class of refusal the
original scout report hit when it tried to empirically verify
`bypassPermissions` hook behaviour ("[Auto-Mode Bypass]") - the
environment's own safety classifier, not Jev or OpenRouter, is in the
way here.

Per the "don't pursue the same outcome through another tool" rule that
denial carries, this demo does **not** attempt direct egress itself.
`demo/run-demo.sh` runs by default with no Jev key configured, which
exercises exactly the `on_unavailable` / breaker code paths (D4/D7) -
a real, useful demo of the fail-closed-to-manual behaviour, just not
of a live Jev round trip. **The System One client's real transport
code is covered by `go test` against a local `httptest` stub (the
transport-failure-matrix tests in `dynamic_test.go`), which is
loopback-only and not a network-egress action.**

To exercise a live round trip, outside this harness (or from an
environment whose policy allows outbound calls to the chosen
provider):

```
echo "sk-or-v1-..." > demo/jev.key   # a real OpenRouter key, hard credit cap
chmod 600 demo/jev.key
./demo/run-demo.sh
```

`jev.key` is git-ignored; never commit a real key.

## Decisions this demo takes as given

Per the captain's D1-D10 record (report.md, bottom): D1 OpenRouter
pinned `jev-1.13`; D2 redacted command text + cwd only; D3 per-user
capped key in a 0600 file; D4 escalate with breaker,
`bypassPermissions → deny` pending Phase 0; D6 allow rules skip the
dynamic layer; D7 off-only env kill switch (not implemented in this
demo - no `BARMKIN_DYNAMIC` env check - since the demo's own config
files are the on/off switch; add it if this graduates past a demo);
D8 regex layer's existing fail-open postures unchanged; D9 SIEM
acceptance deferred; D10 bash-only gating in unattended modes.
