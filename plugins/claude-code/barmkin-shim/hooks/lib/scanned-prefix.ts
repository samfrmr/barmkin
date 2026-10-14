// Shows a scanned prefix of an oversize string instead of withholding all of
// it. Used only for tool results that no injection screen covers: the screened
// untrusted surfaces keep withholding at their limit.
//
// Everything shown was scanned exactly as a string under the limit is: the head
// is cut inside a 16 KiB scan window, at a point no secret match crosses in
// either the raw or the scrubbed view, and then redacted by the unchanged
// two-pass redactInEitherView. Nothing past the cut is ever shown, and nothing
// past the window is ever matched.
//
// A cut is safe when it
//  - is a line boundary or, failing that, a delimiter (a long single line);
//  - is crossed by no rule match in the raw view or in the scrubbed view;
//  - does not follow a PEM private-key header that nothing closes;
//  - scrubs identically in the head and in the window, so no escape sequence or
//    variation-selector run is split;
//  - is not inside the window's last whitespace-free token. Every rule except
//    the PEM block matches within a token (plus the blanks around an `=` or the
//    whitespace after `Bearer`), and a match that needs text past the window
//    cannot be seen from inside it. Keeping the cut before the last token means
//    a value cut off by the window end is never shown.
// If no cut qualifies the caller withholds, as before.
import { REDACTION_RULES, type RedactionRule } from './redaction-rules'
import { redactInEitherView, ruleSpans, WITHHELD_TEXT } from './redaction'
import { isJsSpace, pemScan, type Span } from './linear-scanners'
import { scrubInvisible } from './scrub'

// How much of the string is looked at when choosing the cut, and the longest
// prefix shown.
export const PREFIX_SCAN_CHARS = 16 * 1024
export const PREFIX_KEEP_CHARS = 12 * 1024
const PREFIX_MIN_CHARS = PREFIX_KEEP_CHARS / 2
// A cut whose scrub must be compared with the window's costs a scrub of up to
// the whole head. Content full of invisible characters could make every
// candidate fail that comparison, so only this many are tried before giving up.
const MAX_SCRUB_COMPARISONS = 128
const DELIMITER = /[\s,;(){}[\]<>|"'`]/

export interface ScannedPrefix {
  // The redacted head, ready to show.
  shown: string
  // Where the raw text was cut.
  cut: number
  // Length of the whole raw text.
  total: number
  // Invisible-text carriers in the whole text, for the taint threshold.
  hiddenCount: number
  redactedCount: number
}

interface ViewGuard {
  // Sorted, disjoint spans no cut may fall inside.
  spans: Span[]
  // Start of the last whitespace-free token; no cut may follow it.
  tail: number
}

function mergeOverlapping(spans: Span[]): Span[] {
  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end)
  const out: Span[] = []
  for (const span of sorted) {
    const last = out[out.length - 1]
    if (last && span.start < last.end) last.end = Math.max(last.end, span.end)
    else out.push({ start: span.start, end: span.end })
  }
  return out
}

function guardFor(view: string, rules: RedactionRule[]): ViewGuard {
  const spans: Span[] = []
  for (const rule of rules) spans.push(...ruleSpans(rule, view))
  // A private-key header nothing closes is key material the rule did not match.
  const { unclosedFrom } = pemScan(view)
  if (unclosedFrom >= 0) spans.push({ start: unclosedFrom, end: view.length + 1 })
  let tail = view.length
  while (tail > 0 && !isJsSpace(view.charCodeAt(tail - 1))) tail--
  return { spans: mergeOverlapping(spans), tail }
}

// Whether the cut `c` falls strictly inside a span, or after the last token.
function cutIsUnsafe(guard: ViewGuard, c: number): boolean {
  if (c > guard.tail) return true
  let lo = 0
  let hi = guard.spans.length - 1
  let at = -1
  while (lo <= hi) {
    const mid = (lo + hi) >> 1
    if (guard.spans[mid].start < c) {
      at = mid
      lo = mid + 1
    } else hi = mid - 1
  }
  return at >= 0 && c < guard.spans[at].end
}

// Latest cuts first: line boundaries in the upper half of the keep range, then
// delimiters.
function* candidateCuts(region: string): Generator<number> {
  const top = Math.min(PREFIX_KEEP_CHARS, region.length)
  for (let i = region.lastIndexOf('\n', top - 1); i >= PREFIX_MIN_CHARS; i = region.lastIndexOf('\n', i - 1)) yield i + 1
  for (let c = top; c >= PREFIX_MIN_CHARS; c--) {
    const before = region[c - 1]
    if (before !== '\n' && DELIMITER.test(before)) yield c
  }
}

export function scannedPrefix(
  text: string,
  rules: RedactionRule[] = REDACTION_RULES,
  counters: Record<string, number> = {},
): ScannedPrefix | null {
  const region = text.slice(0, PREFIX_SCAN_CHARS)
  const view = scrubInvisible(region).text
  // With nothing for the scrub to remove, the head scrubs to itself and the
  // two views are the same text.
  const scrubIsIdentity = view === region
  const rawGuard = guardFor(region, rules)
  const viewGuard = scrubIsIdentity ? rawGuard : guardFor(view, rules)

  let comparisons = 0
  for (const c of candidateCuts(region)) {
    if (cutIsUnsafe(rawGuard, c)) continue
    let viewCut = c
    if (!scrubIsIdentity) {
      if (++comparisons > MAX_SCRUB_COMPARISONS) return null
      const headView = scrubInvisible(region.slice(0, c)).text
      if (!view.startsWith(headView)) continue
      viewCut = headView.length
    }
    if (cutIsUnsafe(viewGuard, viewCut)) continue
    const redacted = redactInEitherView(text.slice(0, c), rules, counters)
    if (redacted.text === WITHHELD_TEXT) return null
    return {
      shown: redacted.text,
      cut: c,
      total: text.length,
      // Whole text, not the head: the taint threshold must not be dodged by
      // putting the invisible text past the cut.
      hiddenCount: scrubInvisible(text).hiddenCount,
      redactedCount: redacted.redactedCount,
    }
  }
  return null
}

// The context line that tells the model it is looking at a prefix and how to
// get the rest. `shownChars` counts raw characters of the original text, before
// redaction swaps secrets for placeholders.
export function prefixNotice(shownChars: number, totalChars: number): string {
  return (
    'barmkin: this output is too large to scan whole, so only its first ' +
    shownChars +
    ' of ' +
    totalChars +
    ' characters are included (scanned for secrets); the rest was not shown. To see more, page through it: Read a file with offset and limit, or rerun a narrower command (head, tail, sed -n, grep).'
  )
}
