import type { RedactionRule } from './redaction-rules.js'
import { scrubInvisible } from './scrub'
import type { Span } from './linear-scanners'

export interface RedactionResult {
  text: string
  redactedCount: number
  categories: string[]
}

// Longest string the rules scan: 256 KiB of UTF-16 code units, not bytes. It
// covers the largest inline output Claude Code itself produces (Bash clamps at
// 128,000 characters, Read at 256 KiB). Every rule runs in time linear in the
// text. Most are regexes that are linear as written; the four whose regexes
// backtrack or use lookahead (generic-key-env-assignment, jwt,
// private-key-block, bearer-header) run as the scanners in linear-scanners.ts.
// Measured in the engine, both passes and the invisible-text scrub together
// cost about 0.1 s per MiB on the worst inputs found, and
// tests/redaction-budget.test.ts holds the line at 0.3 s per MiB.
// Longer text is not scanned whole. An unscreened tool result shows a scanned
// prefix of it (scanned-prefix.ts); anywhere else it is withheld.
const MAX_SCANNED_CHARS = 256 * 1024

export function exceedsScanLimit(text: string): boolean {
  return text.length > MAX_SCANNED_CHARS
}

// Longest string the untrusted-content surfaces take whole: a fetched page, an
// MCP result, a file read from outside cwd, a skill body, a peer message, the
// person's prompt and an outbound message. The classifier reads 4,000
// characters of such content, so a larger limit would mostly leave text that
// nothing screened, and a prefix of untrusted text is a decision of its own
// (the oversize-content scout's D2). These surfaces keep withholding at the
// limit the redaction scan used to have.
const MAX_SCREENED_CHARS = 16 * 1024

export function exceedsScreenedLimit(text: string): boolean {
  return text.length > MAX_SCREENED_CHARS
}

// Why a screened surface withheld a string for its size alone, and what to do
// instead. It is a size limit, not a danger, so the advice is to read the
// content in smaller pieces rather than to ask the person.
export const SCREENED_LIMIT_REASON = 'it is longer than the 16 KiB scan limit for untrusted content'
export const PAGING_ADVICE =
  'This is a size limit, not a safety finding: get the content in smaller pieces instead (Read a file with offset and limit, run a narrower command, or ask for a smaller part of the page).'

// Total text one tool result may carry, counted over `result` and its context
// strings: 1 MiB, four strings at the per-string cap. The model-visible `text`
// mirror repeats the same content, so it is not added to the total, but it
// still gets the per-string cap, which makes a worst-case result five full
// strings of 256 KiB. Both redaction passes and the scrub over those 1.25 MiB
// cost about 0.13 s at the rate above, far inside the hook's 10 s budget. (The
// "1-second guard budget" an older version of this comment named is the grace
// a `.catch` handler gets, not the hook's budget.) A result over the total is
// withheld whole. A Read image's base64 payload is one of the strings: it
// survives only while it fits the per-string cap, roughly 190 KiB of image.
// Larger images are withheld with the stated reason, because a prefix of base64
// is not an image.
const MAX_RESULT_CHARS = 1024 * 1024

function textTotals(value: unknown): { total: number; longest: number } {
  if (typeof value === 'string') return { total: value.length, longest: value.length }
  const children = Array.isArray(value) ? value : value && typeof value === 'object' ? Object.values(value) : []
  return children.reduce(
    (acc: { total: number; longest: number }, child) => {
      const sub = textTotals(child)
      return { total: acc.total + sub.total, longest: Math.max(acc.longest, sub.longest) }
    },
    { total: 0, longest: 0 },
  )
}

// How a tool result sits against its budgets: 'within' both, 'long-string' when
// the strings together fit the total but one is over the per-string cap, and
// 'over-total' when the strings together are over the total. `screened` applies
// the limits of an untrusted-content surface instead: a string over
// MAX_SCREENED_CHARS, or strings together over four of them.
export type ResultSize = 'within' | 'long-string' | 'over-total'

export function measureResult(result: unknown, screened = false): ResultSize {
  const maxString = screened ? MAX_SCREENED_CHARS : MAX_SCANNED_CHARS
  const maxTotal = screened ? 4 * MAX_SCREENED_CHARS : MAX_RESULT_CHARS
  const { total, longest } = textTotals(result)
  const rendered = typeof (result as { text?: unknown } | null)?.text === 'string' ? (result as { text: string }).text.length : 0
  if (total - rendered > maxTotal) return 'over-total'
  return longest > maxString ? 'long-string' : 'within'
}

export function exceedsResultBudget(result: unknown): boolean {
  return measureResult(result) !== 'within'
}

// The spans a rule would replace in `text`: its linear scanner when it has
// one, else its regex. Spans come back in left-to-right, non-overlapping order
// and are those `String.prototype.replace` would substitute.
export function ruleSpans(rule: RedactionRule, text: string): Span[] {
  if (rule.scan) return rule.scan(text)
  const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : rule.pattern.flags + 'g'
  const out: Span[] = []
  for (const m of text.matchAll(new RegExp(rule.pattern.source, flags))) {
    const start = m.index ?? 0
    out.push({ start, end: start + m[0].length })
  }
  return out
}

// Whether the rule matches anywhere in `text`.
function ruleMatches(rule: RedactionRule, text: string): boolean {
  if (rule.scan) return rule.scan(text).length > 0
  rule.pattern.lastIndex = 0
  return rule.pattern.test(text)
}

// Replaces every secret match with a placeholder token, numbered per
// category. No reversible map is kept anywhere: once a value is replaced,
// the original text is gone from this function's output, and the caller
// must not log the input. `counters` is caller-owned so a whole tool
// result (which may run several rules) gets consistent numbering, and so
// a caller can keep counting across multiple calls in the same turn.
export function redactText(
  text: string,
  rules: readonly RedactionRule[],
  counters: Record<string, number> = {},
): RedactionResult {
  if (exceedsScanLimit(text)) {
    counters.oversized = (counters.oversized ?? 0) + 1
    return { text: `[REDACTED:oversized#${counters.oversized}]`, redactedCount: 1, categories: ['oversized'] }
  }
  let result = text
  let redactedCount = 0
  const categoriesHit = new Set<string>()

  for (const rule of rules) {
    const placeholder = (): string => {
      counters[rule.category] = (counters[rule.category] ?? 0) + 1
      redactedCount++
      categoriesHit.add(rule.category)
      return `[REDACTED:${rule.category}#${counters[rule.category]}]`
    }
    if (!rule.scan) {
      result = result.replace(rule.pattern, placeholder)
      continue
    }
    let replaced = ''
    let last = 0
    for (const span of rule.scan(result)) {
      replaced += result.slice(last, span.start) + placeholder()
      last = span.end
    }
    result = replaced + result.slice(last)
  }

  return { text: result, redactedCount, categories: [...categoriesHit] }
}

// Matches on the original text or its scrubbed view, so a zero-width character
// can neither hide a secret from the rules nor split one into a match.
export function containsSecretInEitherView(text: string, rules: readonly RedactionRule[]): boolean {
  return containsAnySecret(text, rules) || containsAnySecret(scrubInvisible(text).text, rules)
}

// The second pass runs on the first pass's output. A placeholder can be longer
// than the match it replaces, so the first pass's output can pass the scan limit,
// and redactText would then collapse the second pass's input into an oversized
// placeholder. Output that grows past the limit is withheld with a stated reason
// instead. The second pass's own output can also grow, but it is never fed back
// into redactText, so it is returned as is and not collapsed.
export const WITHHELD_TEXT = 'barmkin: withheld, the redacted text exceeds the 256 KiB scan limit'

// The classifier must not score a withheld marker or an oversize placeholder as
// content, so such input yields no classifier payload. The screen then falls
// back to the local heuristics only, and the classifier is not called.
export function classifierInput(
  text: string,
  rules: readonly RedactionRule[],
  counters: Record<string, number>,
): string | null {
  if (exceedsScanLimit(text)) return null
  const redacted = redactInEitherView(text, rules, counters)
  return redacted.text === WITHHELD_TEXT ? null : redacted.text
}

export function redactInEitherView(
  text: string,
  rules: readonly RedactionRule[],
  counters: Record<string, number>,
): { text: string; redactedCount: number } {
  const first = redactText(text, rules, counters)
  if (exceedsScanLimit(first.text)) {
    return { text: WITHHELD_TEXT, redactedCount: first.redactedCount + 1 }
  }
  const second = redactText(scrubInvisible(first.text).text, rules, counters)
  return { text: second.text, redactedCount: first.redactedCount + second.redactedCount }
}

export function containsAnySecret(text: string, rules: readonly RedactionRule[]): boolean {
  if (exceedsScanLimit(text)) return false
  return rules.some((rule) => ruleMatches(rule, text))
}
