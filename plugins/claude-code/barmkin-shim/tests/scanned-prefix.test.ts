import { expect, test } from 'claude-code/testing'
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactInEitherView } from '../hooks/lib/redaction'
import { prefixNotice, scannedPrefix, PREFIX_KEEP_CHARS, PREFIX_SCAN_CHARS } from '../hooks/lib/scanned-prefix'
import { ALNUM, B64, pemHeader, randOf } from './fuzz-support'
import { filler, fillerTo, leaks } from './prefix-fuzz-support'

const KEEP = PREFIX_KEEP_CHARS

// ---------------------------------------------------------------------------
// Per-rule straddles, in the raw view and in the scrubbed view.
// ---------------------------------------------------------------------------

function pieces(secret: string): string[] {
  const out: string[] = []
  for (let i = 0; i + 12 <= secret.length; i++) out.push(secret.slice(i, i + 12))
  return out
}

function straddleText(secret: string, offset: number, oneLine: boolean): string {
  const r = randOf(offset + secret.length)
  const lead = fillerTo(r, KEEP - offset, oneLine)
  return lead + secret + (oneLine ? ' ' : '\n') + filler(r, 8 * 1024, oneLine)
}

for (const rule of REDACTION_RULES) {
  for (const oneLine of [false, true]) {
    test('a ' + rule.name + ' match across the cut is never shown in part (' + (oneLine ? 'one line' : 'multi-line') + ', raw and scrubbed views)', () => {
      const example = rule.example
      const mid = Math.floor(example.length / 2)
      // The scrubbed view: a zero-width space inside the match, so the raw text
      // has no match and the scrubbed text does. A second variant puts one
      // between two characters that would otherwise stay apart.
      const variants = [example, example.slice(0, mid) + '\u200b' + example.slice(mid)]
      for (const variant of variants) {
        for (const offset of [1, 2, Math.floor(variant.length / 3), mid, variant.length - 2, variant.length - 1]) {
          const text = straddleText(variant, offset, oneLine)
          const prefix = scannedPrefix(text, REDACTION_RULES, {})
          expect(prefix).not.toBeNull()
          const clean = example
          for (const piece of pieces(clean)) {
            if (prefix?.shown.includes(piece)) throw new Error(rule.name + ' leaked ' + JSON.stringify(piece) + ' at offset ' + offset)
          }
          // Nothing of the match survives, whole or in part: the example's own
          // text is gone, or the cut fell before it.
          expect(prefix?.shown.includes('\u200b')).toBe(false)
        }
      }
    })
  }
}

// ---------------------------------------------------------------------------
// Cuts that would split something.
// ---------------------------------------------------------------------------

test('an unclosed private-key header stops the prefix before it', () => {
  const r = randOf(1)
  const body = Array.from({ length: 200 }, () => r.chars(B64, 64)).join('\n')
  for (const at of [3000, 9000, 11000, 12000]) {
    const text = fillerTo(r, at, false) + pemHeader('BEGIN', 'RSA ') + '\n' + body + '\nmore text\n' + filler(r, 4000, false)
    const prefix = scannedPrefix(text, REDACTION_RULES, {})
    // Cut before the header: when that leaves under half the keep range there is no safe cut.
    if (at < KEEP / 2) expect(prefix).toBeNull()
    else {
      expect(prefix).not.toBeNull()
      expect(prefix?.cut).toBeLessThanOrEqual(at)
      expect(prefix?.shown.includes('BEGIN')).toBe(false)
      for (const line of body.split('\n').slice(0, 20)) expect(prefix?.shown.includes(line.slice(0, 12))).toBe(false)
    }
  }
})

test('a private-key block closed past the scan window still stops the prefix before its header', () => {
  const r = randOf(2)
  const body = Array.from({ length: 400 }, () => r.chars(B64, 64)).join('\n')
  const text = fillerTo(r, 10000, false) + pemHeader('BEGIN') + '\n' + body + '\n' + pemHeader('END') + '\n' + filler(r, 2000, false)
  expect(text.indexOf('-----END')).toBeGreaterThan(PREFIX_SCAN_CHARS)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(prefix?.cut).toBeLessThanOrEqual(10000)
  expect(prefix?.shown.includes('BEGIN')).toBe(false)
})

test('a closed private-key block before the cut is redacted and shown', () => {
  const r = randOf(3)
  const block = pemHeader('BEGIN') + '\n' + Array.from({ length: 5 }, () => r.chars(B64, 64)).join('\n') + '\n' + pemHeader('END') + '\n'
  const text = fillerTo(r, 3000, false) + block + filler(r, 20000, false)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix?.shown).toContain('[REDACTED:private-key#1]')
  expect(prefix?.shown.includes('BEGIN')).toBe(false)
  expect(prefix?.cut).toBeGreaterThan(KEEP - 400)
})

test('a variation-selector run is not split by the cut', () => {
  // Four selectors are a run, and the scrub removes them. A vertical tab, which
  // the scrub also removes, sits inside the run and is also a delimiter, so a
  // cut right after it would show two selectors the whole text hides.
  const r = randOf(4)
  const head = fillerTo(r, KEEP - 3, true)
  const text = head + '\ufe00\ufe01\u000b\ufe02\ufe03' + 'x'.repeat(5000) + ' ' + filler(r, 8000, true)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(prefix?.shown).not.toMatch(/[\ufe00-\ufe0f]/)
  expect(prefix?.cut).toBeLessThanOrEqual(KEEP - 3)
})

test('an OSC escape sequence is not split by the cut', () => {
  // The payload sits between semicolons, which are delimiters, so a cut could
  // fall inside the sequence and leave its payload as visible text.
  const r = randOf(5)
  const head = fillerTo(r, KEEP - 6, true)
  const text = head + '\u001b]8;;https://evil.example/payload\u0007link text ' + filler(r, 9000, true)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(prefix?.shown).not.toContain('evil.example')
  expect(prefix?.shown).not.toContain(']8;')
  expect(prefix?.cut).toBeLessThanOrEqual(KEEP - 4)
})

test('a value cut off by the end of the scan window is not shown', () => {
  // Each of these needs text past the window to be a match, so the window alone
  // finds none. Their whitespace-free run reaches the window's end, so the cut
  // must fall before it.
  const r = randOf(6)
  const run = (n: number) => r.chars(ALNUM + ',;(){}[]<>|', n).replace(/\s/g, 'a')
  const cases: Array<[string, string, string]> = [
    ['a quoted assignment whose closing quote is past the window', 'DB_PASSWORD="', '"'],
    ['a JWT whose first dot is past the window', 'eyJ', '.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w'],
    ['a URL password whose @ is past the window', 'postgres://app:', '@db.internal/main'],
    ['a bearer token whose digit is past the window', 'Bearer ', '9'],
  ]
  for (const [label, open, close] of cases) {
    // One line, so the run's own delimiters are candidate cuts.
    const lead = fillerTo(r, 9000, true)
    const body = run(8000)
    const text = lead + open + body + close + ' tail ' + filler(r, 3000, true)
    const prefix = scannedPrefix(text, REDACTION_RULES, {})
    expect(prefix).not.toBeNull()
    // At most the opening: a `Bearer ` ending in a space is itself a cut point.
    expect(prefix?.cut).toBeLessThanOrEqual(9000 + open.length)
    if (leaks(prefix?.shown ?? '', [body])) throw new Error(label + ' leaked')
    expect((prefix?.shown ?? '').includes(body.slice(0, 12))).toBe(false)
  }
})

test('a single very long line is cut at a delimiter', () => {
  const r = randOf(7)
  const text = filler(r, 90 * 1024, true)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(prefix?.cut).toBeGreaterThan(KEEP - 200)
  expect(prefix?.cut).toBeLessThanOrEqual(KEEP)
  expect(text.charAt((prefix?.cut ?? 0) - 1)).toBe(' ')
  expect(prefix?.shown).toBe(text.slice(0, prefix?.cut))
})

test('lines are preferred to delimiters, and the cut is the latest one', () => {
  const r = randOf(8)
  const text = filler(r, 60 * 1024, false)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(text.charAt((prefix?.cut ?? 0) - 1)).toBe('\n')
  expect(text.indexOf('\n', prefix?.cut)).toBeGreaterThan(KEEP - 1)
})

test('redacts what it shows with the unchanged two-pass function', () => {
  const r = randOf(9)
  const key = 'AKIAIOSFODNN7EXAMPLE'
  const text = fillerTo(r, 2000, false) + 'aws ' + key + '\n' + filler(r, 40000, false)
  const counters: Record<string, number> = {}
  const prefix = scannedPrefix(text, REDACTION_RULES, counters)
  expect(prefix?.shown).toContain('[REDACTED:aws-key#1]')
  expect(prefix?.shown).not.toContain(key)
  expect(prefix?.redactedCount).toBe(1)
  expect(counters['aws-key']).toBe(1)
  expect(prefix?.shown).toBe(redactInEitherView(text.slice(0, prefix?.cut), REDACTION_RULES, {}).text)
  expect(prefix?.total).toBe(text.length)
})

test('counts invisible text over the whole string, however far past the cut it sits', () => {
  const r = randOf(10)
  const tags = Array.from({ length: 40 }, (_, i) => String.fromCodePoint(0xe0041 + (i % 20))).join('')
  const text = fillerTo(r, 20000, false) + tags + filler(r, 30000, false)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix).not.toBeNull()
  expect(prefix?.hiddenCount).toBe(40)
  expect(prefix?.shown).not.toMatch(/[\u{e0000}-\u{e007f}]/u)
})

test('the prefix is shown in full when nothing is hidden by the scrub', () => {
  const r = randOf(11)
  const text = filler(r, 50 * 1024, false)
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(prefix?.shown).toBe(text.slice(0, prefix?.cut))
  expect(prefix?.hiddenCount).toBe(0)
})

// ---------------------------------------------------------------------------
// No safe cut: withhold, and quickly.
// ---------------------------------------------------------------------------

function fillWith(unit: string, size: number): string {
  return unit.repeat(Math.ceil(size / unit.length)).slice(0, size)
}

test('pathological runs have no safe cut and are withheld inside 200 ms', () => {
  const size = 300 * 1024
  const inputs: Record<string, string> = {
    'SECRET= run': fillWith('SECRET=', size),
    'eyJ- run': fillWith('eyJ-', size),
    'one token with no whitespace': 'a'.repeat(size),
    'PEM BEGIN lines': fillWith(pemHeader('BEGIN') + '\n', size),
    'secret assignments on every line': fillWith('API_KEY=abcdef0123456789abcd\n', size),
    'escape sequences split by delimiters': fillWith('\u001b[1;31;4m', size),
    'selectors split by vertical tabs': fillWith('\ufe00\ufe01\u000b\ufe02\ufe03\u000b', size),
    'a delimiter before every character of a long token': fillWith('(a', size),
  }
  for (const [label, text] of Object.entries(inputs)) {
    let best = Infinity
    let prefix = null as ReturnType<typeof scannedPrefix>
    for (let run = 0; run < 3; run++) {
      const started = performance.now()
      prefix = scannedPrefix(text, REDACTION_RULES, {})
      best = Math.min(best, performance.now() - started)
    }
    if (best >= 200) throw new Error(label + ' took ' + best + ' ms')
    // Whitespace-free input has nowhere to cut. A line of secrets after another
    // does: each line is a whole match, so the cut lands between two of them and
    // everything shown is a placeholder.
    if (label === 'secret assignments on every line') {
      expect(prefix).not.toBeNull()
      expect(prefix?.shown.includes('abcdef')).toBe(false)
      expect(prefix?.shown).toContain('[REDACTED:env-key#')
    } else if (label !== 'selectors split by vertical tabs') {
      expect(prefix).toBeNull()
    }
  }
})

test('realistic oversize logs are cut in a few milliseconds', () => {
  const r = randOf(12)
  const text = filler(r, 600 * 1024, false)
  const started = performance.now()
  const prefix = scannedPrefix(text, REDACTION_RULES, {})
  expect(performance.now() - started < 200).toBe(true)
  expect(prefix).not.toBeNull()
})

test('says how much is shown and how to page', () => {
  const notice = prefixNotice(12281, 301234)
  expect(notice).toContain('12281')
  expect(notice).toContain('301234')
  expect(notice).toContain('offset and limit')
})
