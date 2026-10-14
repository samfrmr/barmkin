// Generates golden.json: barmkin-mod's own TypeScript screen run over
// recorded mock Jev responses, for golden_test.go to replay against the Go
// port. It makes no network call. Run it with Node 24 or later, pointing
// BARMKIN_MOD at a barmkin-mod checkout:
//
//   BARMKIN_MOD=/path/to/barmkin-mod node golden.gen.ts > golden.json
//
// The screen step mirrors screenContent in barmkin-mod's hooks/register.ts
// (its withExfiltration and classifier-gap step are not exported, so they
// are restated here line for line); everything else is barmkin-mod's code.

import { registerHooks } from "node:module"
import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { pathToFileURL } from "node:url"

// barmkin-mod imports its siblings without an extension.
registerHooks({
  resolve(specifier, context, next) {
    try {
      return next(specifier, context)
    } catch (error) {
      if (specifier.startsWith(".")) return next(specifier + ".ts", context)
      throw error
    }
  },
})

const root = process.env.BARMKIN_MOD
if (!root) throw new Error("set BARMKIN_MOD to a barmkin-mod checkout")
const lib = (name: string) => import(pathToFileURL(`${root}/hooks/lib/${name}.ts`).href)
const taint = await lib("taint")
const windows = await lib("classifier-windows")
const client = await lib("system-one-client")
const questions = await lib("jev-questions")

const MODEL = "jev-1.13.0"

// A recorded endpoint response: a status and body, or a call that timed
// out or could not connect.
type Mock = { status: number; body: string } | { timeout: true } | { network: true }

function answer(scores: Record<string, number>, model = MODEL): Mock {
  const answers: Record<string, unknown> = {}
  for (const [id, p] of Object.entries(scores)) answers[id] = { type: "noul", noul: p }
  return { status: 200, body: JSON.stringify({ model, answers }) }
}
const prod = (injection: number, exfiltration: number, credentials: number, model = MODEL) =>
  answer({ injection, exfiltration, credentials }, model)
const timeout: Mock = { timeout: true }
const network: Mock = { network: true }
const http = (status: number): Mock => ({ status, body: "{}" })

type ParseResult = { ok: true; answers: Record<string, number>; model: string } | { ok: false; reason: string }

// What the client makes of one recorded response.
function parse(mock: Mock, ids: string[]): ParseResult {
  if ("timeout" in mock) return { ok: false, reason: "timeout" }
  if ("network" in mock) return { ok: false, reason: "network: refused" }
  if (mock.status < 200 || mock.status > 299) return { ok: false, reason: "http_" + mock.status }
  let parsed: unknown
  try {
    parsed = JSON.parse(mock.body)
  } catch {
    return { ok: false, reason: "malformed_response: not JSON" }
  }
  return client.parseSystemOneResponse(parsed, ids, client.JEV_MODEL_PATTERN)
}

// register.ts's isTransient.
function isTransient(reason: string): boolean {
  return reason === "timeout" || reason.startsWith("network") || reason === "http_429" || /^http_5\d\d$/.test(reason)
}

// register.ts's classifyWindows over recorded responses: the first answer,
// then the second for a window whose first failed for a transient reason.
function classifyWindows(mocks: Mock[][], ids: string[], retry: boolean): { results: ParseResult[]; calls: number[] } {
  const results: ParseResult[] = []
  const calls: number[] = []
  mocks.forEach((m) => {
    let r = parse(m[0], ids)
    let n = 1
    if (retry && !r.ok && isTransient(r.reason)) {
      r = parse(m[1], ids)
      n = 2
    }
    results.push(r)
    calls.push(n)
  })
  return { results, calls }
}

// register.ts's withExfiltration.
function withExfiltration(screened: any, exfiltration: number, jevModel: string | null): any {
  const scores = { ...screened.scores, exfiltration }
  if (screened.tainted || jevModel === null || exfiltration < taint.DEFAULT_TAINT_THRESHOLDS.taintAt) return { ...screened, scores }
  return {
    ...screened,
    decision: "escalate",
    tainted: true,
    reason: `content scored ${exfiltration.toFixed(2)} on the data-exfiltration question (>= ${taint.DEFAULT_TAINT_THRESHOLDS.taintAt})`,
    question: "exfiltration",
    probability: exfiltration,
    model: jevModel,
    scores,
  }
}

interface ScreenCase {
  name: string
  source: string
  text: string // a key of texts
  configured: boolean
  local: { injection: number; credentials: number }
  production?: Mock[][] // per window: the first response, then the retry's
  shadow?: { captain: Mock[]; revised: Mock[] } // per window, asked once
}

function screen(c: ScreenCase) {
  const text = built[c.text]
  const plan = windows.planWindows(text)
  const texts = plan.windows.map((w: { start: number; end: number }) => text.slice(w.start, w.end))
  const local = { model: "heuristic", injection: c.local.injection, credentials: c.local.credentials }
  let results: (ParseResult | null)[] = texts.map(() => null)
  let calls: number[] = texts.map(() => 0)
  if (c.configured) {
    const production = c.production ?? texts.map(() => [prod(0, 0, 0)])
    if (production.length !== texts.length) throw new Error(c.name + ": " + texts.length + " windows")
    ;({ results, calls } = classifyWindows(production, [...questions.PRODUCTION_QUESTION_IDS], true))
  }
  // screenContent's production step.
  const jevScores = windows.mergeWindowScores(results)
  const screened = withExfiltration(taint.composeScreen(local, jevScores), jevScores?.exfiltration ?? 0, jevScores?.model ?? null)
  const unclassified = c.configured
    ? windows.unclassifiedChars(text.length, plan.windows, results.map((r) => r?.ok === true))
    : 0
  const gapText = screened.decision === "deny" ? null : taint.classifierGapReason(c.configured, text.length, unclassified)
  const composed = gapText
    ? { ...screened, tainted: true, decision: "escalate", reason: screened.tainted ? screened.reason : gapText }
    : screened
  // The closed codes the monitor reports in place of barmkin-mod's prose.
  const gap = gapText === null ? "none" : plan.covered < text.length ? "scan_limit" : "unclassified"
  const reason = !screened.tainted && gapText
    ? "gap_" + gap
    : composed.decision === "pass"
      ? "below_thresholds"
      : screened.question === "injection" && composed.decision === "deny"
        ? "injection_deny"
        : screened.question

  const out: any = {
    name: c.name,
    source: c.source,
    text: c.text,
    configured: c.configured,
    local: { injection: c.local.injection, credentials: c.local.credentials, exfiltration: 0 },
    production: c.production ?? null,
    calls,
    want: {
      decision: composed.decision,
      scores: composed.scores,
      reason,
      gap,
      raised: {
        untrusted: composed.tainted ? c.source : "none",
        sensitive: screened.scores.credentials >= taint.DEFAULT_TAINT_THRESHOLDS.taintAt ? "credential" : "none",
      },
      mod_reason: composed.reason,
    },
  }
  if (c.shadow) {
    out.shadow = c.shadow
    out.want_shadow = questions.SHADOW_ARMS.map((arm: string) => {
      const ids = Object.keys(questions.shadowQuestions(arm))
      const { results } = classifyWindows((c.shadow as any)[arm].map((m: Mock) => [m]), ids, false)
      const merged = windows.mergeWindowAnswers(results, ids)
      return { arm, windows: results.length, answered: merged?.answered ?? 0, scores: merged?.answers ?? {} }
    })
  }
  return out
}

// A deterministic PRNG, so the texts are the same on every run. golden_test.go
// rebuilds each text from its spec and checks its SHA-256.
function rng(seed: number) {
  let s = seed >>> 0
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0
    return s / 2 ** 32
  }
}

// A text: `n` UTF-16 code units of `pieces` picked by a seeded PRNG, or one
// piece repeated `n` times.
type TextSpec = { pieces: string[]; n: number; seed: number } | { repeat: string; n: number }

function build(spec: TextSpec): string {
  if ("repeat" in spec) return spec.repeat.repeat(spec.n)
  const next = rng(spec.seed)
  let out = ""
  while (out.length < spec.n) out += spec.pieces[Math.floor(next() * spec.pieces.length)]
  out = out.slice(0, spec.n)
  // Never end on half a surrogate pair.
  const last = out.charCodeAt(out.length - 1)
  return last >= 0xd800 && last <= 0xdbff ? out.slice(0, -1) + "." : out
}

const WORDS = ["the ", "build ", "page ", "returns ", "a ", "list ", "of ", "items, ", "and ", "then ", "stops. ", "\n"]
const PLACEHOLDERS = ["token=[REDACTED:github-token#1] ", "[REDACTED:aws-secret-access-key#12]", "key [REDACTED:slack-webhook#3]. "]
const SURROGATES = ["🏰", "déjà", "𝒳", "ok", "🙂🙂", "\u00a0", "\u3000"]

const texts: Record<string, TextSpec> = {
  "empty": { repeat: "x", n: 0 },
  "short": { repeat: "Fetched page: the build returns a list of items. ", n: 1 },
  "exactly one window": { repeat: "x", n: 4000 },
  "one unit past a window": { repeat: "x", n: 4001 },
  "words over two windows": { pieces: WORDS, n: 6000, seed: 1 },
  "words past the last window": { pieces: WORDS, n: 20000, seed: 2 },
  "no whitespace past the last window": { repeat: "abcdefghij", n: 1900 },
  "placeholders across cuts": { pieces: [...WORDS, ...PLACEHOLDERS, ...PLACEHOLDERS], n: 12000, seed: 3 },
  "placeholders without whitespace": { pieces: ["[REDACTED:a-b#77]", "[REDACTED:github-token#123]", "xy"], n: 9000, seed: 4 },
  "surrogate pairs at every cut": { pieces: SURROGATES, n: 14000, seed: 5 },
  "astral only": { repeat: "🏰", n: 5000 },
  "unicode whitespace": { pieces: ["word", "\u2028", "\u205f", "\ufeff", "\u1680", "\u000b"], n: 9000, seed: 6 },
}
for (let k = 0; k < 6; k++) {
  texts["mixed " + k] = { pieces: [...WORDS, ...PLACEHOLDERS, ...SURROGATES], n: 4000 + k * 2311, seed: 100 + k }
}
const built: Record<string, string> = {}
for (const [name, spec] of Object.entries(texts)) built[name] = build(spec)

const plans = Object.keys(texts).map((name) => {
  const plan = windows.planWindows(built[name])
  return { text: name, windows: plan.windows, covered: plan.covered }
})

const short = "short"
const two = "words over two windows"
const three = "unicode whitespace"
const long = "words past the last window"
const four = [prod(0.01, 0.02, 0.03), prod(0.01, 0.02, 0.03)]

const cases: ScreenCase[] = [
  { name: "not configured, clean", source: "fetch", text: short, configured: false, local: { injection: 0, credentials: 0 } },
  { name: "not configured, heuristic escalates", source: "mcp", text: short, configured: false, local: { injection: 0.65, credentials: 0 } },
  { name: "not configured, heuristic cap never denies", source: "mcp", text: short, configured: false, local: { injection: 0.8, credentials: 0.9 } },
  { name: "not configured, long content has no gap", source: "read", text: long, configured: false, local: { injection: 0, credentials: 0 } },
  { name: "clean answer passes", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.02, 0.01, 0.0)]] },
  { name: "jev raises injection to escalate", source: "fetch", text: short, configured: true, local: { injection: 0.3, credentials: 0 }, production: [[prod(0.6, 0.1, 0.1)]] },
  { name: "jev denies on injection", source: "mcp", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.91, 0.2, 0.5)]] },
  { name: "deny exactly at the line", source: "mcp", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.85, 0, 0)]] },
  { name: "escalate exactly at the line", source: "peer", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.5, 0, 0)]] },
  { name: "jev never lowers a local score", source: "read", text: short, configured: true, local: { injection: 0.65, credentials: 0.9 }, production: [[prod(0.01, 0.01, 0.01)]] },
  { name: "credentials escalate and raise the sensitive leg", source: "read", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.1, 0.1, 0.7)]] },
  { name: "local secret scan raises the sensitive leg", source: "skill", text: short, configured: true, local: { injection: 0, credentials: 0.9 }, production: [[prod(0, 0, 0)]] },
  { name: "exfiltration escalates on its own", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.1, 0.72, 0.1)]] },
  { name: "exfiltration keeps an injection reason", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.55, 0.9, 0.1)]] },
  { name: "deny with credentials keeps both legs", source: "mcp", text: short, configured: true, local: { injection: 0, credentials: 0.9 }, production: [[prod(0.95, 0.9, 0.95)]] },
  { name: "one window fails: degrades to local, no gap", source: "fetch", text: short, configured: true, local: { injection: 0.3, credentials: 0 }, production: [[http(503), http(503)]] },
  { name: "one window times out twice", source: "mcp", text: short, configured: true, local: { injection: 0.65, credentials: 0 }, production: [[timeout, timeout]] },
  { name: "transient failure answered on retry", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[http(429), prod(0.7, 0, 0)]] },
  { name: "network failure answered on retry", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[network, prod(0.1, 0.1, 0.1)]] },
  { name: "timeout answered on retry", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[timeout, prod(0.2, 0.1, 0.1)]] },
  { name: "refusal is not retried", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[http(401), prod(0.9, 0, 0)]] },
  { name: "malformed answer is not retried", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[{ status: 200, body: "not json" }, prod(0.9, 0, 0)]] },
  { name: "wrong model is not an answer", source: "fetch", text: short, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.99, 0, 0, "jev-2.0"), prod(0.99, 0, 0)]] },
  { name: "two windows, both answer: highest wins", source: "mcp", text: two, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.2, 0.6, 0.1)], [prod(0.4, 0.1, 0.3)]] },
  { name: "two windows, one fails: unclassified gap", source: "mcp", text: two, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.1, 0.1, 0.1)], [http(500), http(502)]] },
  { name: "two windows, both fail: gap over local", source: "fetch", text: two, configured: true, local: { injection: 0.3, credentials: 0 }, production: [[timeout, timeout], [network, network]] },
  { name: "gap keeps a tainted reason", source: "fetch", text: two, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.6, 0, 0)], [http(400)]] },
  { name: "deny drops the gap", source: "mcp", text: three, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.2, 0, 0)], [prod(0.9, 0, 0)], [http(503), http(503)]] },
  { name: "failed window never lowers a score", source: "fetch", text: three, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0.4, 0.3, 0.2)], [{ status: 200, body: '{"model":"jev-1.13.0","answers":{}}' }], [prod(0.1, 0.45, 0.1)]] },
  { name: "content past the last window: scan-limit gap", source: "read", text: long, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0, 0, 0)], [prod(0, 0, 0)], [prod(0, 0, 0)], [prod(0, 0, 0)], [prod(0, 0, 0)]] },
  { name: "scan-limit gap with an escalate keeps its reason", source: "read", text: long, configured: true, local: { injection: 0, credentials: 0 }, production: [[prod(0, 0, 0)], [prod(0, 0.8, 0)], [prod(0, 0, 0)], [prod(0, 0, 0)], [timeout, timeout]] },
  {
    name: "shadow answers are annotation only",
    source: "fetch", text: two, configured: true, local: { injection: 0, credentials: 0 },
    production: [[prod(0.1, 0.1, 0.1)], [prod(0.1, 0.1, 0.1)]],
    shadow: {
      captain: [answer({ injection: 0.99, exfiltration: 0.98, credentials: 0.97, destructive_command: 0.96 }), answer({ injection: 0.2, exfiltration: 0.1, credentials: 0.3, destructive_command: 0.4 })],
      revised: [answer({ destructive_command: 0.95 }), answer({ destructive_command: 0.1 })],
    },
  },
  {
    name: "shadow failures are partial annotations",
    source: "mcp", text: two, configured: true, local: { injection: 0, credentials: 0 },
    production: four.map((m) => [m]),
    shadow: { captain: [http(503), answer({ injection: 0.3, exfiltration: 0.2, credentials: 0.1, destructive_command: 0.6 })], revised: [timeout, network] },
  },
]

// Strict parsing: recorded bodies and what barmkin-mod's parser made of them.
const ids = [...questions.PRODUCTION_QUESTION_IDS]
const ans = (p: unknown) => ({ type: "noul", noul: p })
const parseBodies: { name: string; body: string }[] = [
  { name: "valid", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(0.1), exfiltration: ans(0), credentials: ans(1) } }) },
  { name: "valid, longer model spelling", body: JSON.stringify({ model: "openrouter/jev-1.13.2-preview", answers: { injection: ans(0.5), exfiltration: ans(0.25), credentials: ans(0.125) } }) },
  { name: "valid, extra top-level and answer fields", body: JSON.stringify({ model: "jev-1.13.0", usage: { tokens: 9 }, answers: { injection: { ...ans(0.1), why: "x" }, exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "valid, exponent and negative zero", body: '{"model":"jev-1.13.0","answers":{"injection":{"type":"noul","noul":1e-3},"exfiltration":{"type":"noul","noul":-0},"credentials":{"type":"noul","noul":1.0}}}' },
  { name: "array body", body: "[]" },
  { name: "null body", body: "null" },
  { name: "string body", body: '"jev-1.13.0"' },
  { name: "missing model", body: JSON.stringify({ answers: { injection: ans(0), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "wrong model", body: JSON.stringify({ model: "jev-1.12.0", answers: { injection: ans(0), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "model prefix only", body: JSON.stringify({ model: "jev-1.130", answers: { injection: ans(0), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "numeric model", body: JSON.stringify({ model: 1.13, answers: { injection: ans(0), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "answers missing", body: JSON.stringify({ model: "jev-1.13.0" }) },
  { name: "answers null", body: JSON.stringify({ model: "jev-1.13.0", answers: null }) },
  { name: "answers array", body: JSON.stringify({ model: "jev-1.13.0", answers: [] }) },
  { name: "too few answers", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(0), exfiltration: ans(0) } }) },
  { name: "extra answer", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(0), exfiltration: ans(0), credentials: ans(0), destructive_command: ans(0) } }) },
  { name: "renamed answer", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(0), exfiltration: ans(0), credential: ans(0) } }) },
  { name: "answer null", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: null, exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "answer array", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: [], exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "wrong answer type", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: { type: "bool", noul: 0 }, exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "capitalised keys", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: { Type: "noul", Noul: 0.9 }, exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "string probability", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans("0.9"), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "boolean probability", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(true), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "probability above one", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(1.01), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "negative probability", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: ans(-0.01), exfiltration: ans(0), credentials: ans(0) } }) },
  { name: "overflowing probability", body: '{"model":"jev-1.13.0","answers":{"injection":{"type":"noul","noul":1e400},"exfiltration":{"type":"noul","noul":0},"credentials":{"type":"noul","noul":0}}}' },
  { name: "probability missing", body: JSON.stringify({ model: "jev-1.13.0", answers: { injection: { type: "noul" }, exfiltration: ans(0), credentials: ans(0) } }) },
]
const parses = parseBodies.map(({ name, body }) => {
  let parsed: unknown
  let r: ParseResult
  try {
    parsed = JSON.parse(body)
    r = client.parseSystemOneResponse(parsed, ids, client.JEV_MODEL_PATTERN)
  } catch {
    r = { ok: false, reason: "not JSON" }
  }
  return { name, body, ok: r.ok, answers: r.ok ? r.answers : null, model: r.ok ? r.model : null }
})

// The request bodies barmkin-mod sends, for one window under each set.
const requests = [
  { set: "production", body: client.buildSystemOneRequest(MODEL, { content: built[short] }, questions.PRODUCTION_QUESTIONS) },
  ...questions.SHADOW_ARMS.map((arm: string) => ({ set: arm, body: client.buildSystemOneRequest(MODEL, { content: built[short] }, questions.shadowQuestions(arm)) })),
]

const sha256 = (text: string) => createHash("sha256").update(text, "utf8").digest("hex")

let commit = "unknown"
try {
  commit = execFileSync("git", ["-C", root, "rev-parse", "HEAD"], { encoding: "utf8" }).trim()
} catch {}

process.stdout.write(
  JSON.stringify({
    generated_from: "barmkin-mod " + commit,
    model: MODEL,
    texts: Object.fromEntries(Object.entries(texts).map(([name, spec]) => [name, { ...spec, sha256: sha256(built[name]) }])),
    plans,
    parses,
    requests,
    screens: cases.map(screen),
  }, null, 1) + "\n",
)
