// Exact, linear-time replacements for the four redaction rules whose regexes
// are expensive on crafted input: generic-key-env-assignment, jwt,
// private-key-block (each backtracks quadratically) and bearer-header (it uses
// lookahead). Each scanner returns the same left-to-right, non-overlapping
// spans that `String.prototype.replace` with the rule's `g` regex would
// replace, so redactText can use them in place of the regex at any text size.
// Indices are UTF-16 code units, as in the regex engine.
//
// The regexes stay in redaction-rules.ts as the specification: they supply the
// example vectors and are the reference tests/linear-scanners.test.ts compares
// these scanners against on seeded fuzz.
//
// The quadratic shapes share one cause: at every candidate start the regex
// rescans the same character run (the value after each `NAME=`, the segment
// after each `eyJ`, the body after each unclosed BEGIN). A run's end, and
// whether it holds a digit or `${`, are properties of the run, so each scanner
// computes them once and reuses them for every candidate start inside it.

export interface Span {
  start: number
  end: number
}

export type SpanScanner = (text: string) => Span[]

const isWord = (c: number): boolean => (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 95
const isDigit = (c: number): boolean => c >= 48 && c <= 57
const isLetter = (c: number): boolean => (c >= 65 && c <= 90) || (c >= 97 && c <= 122)

// JavaScript's `\s`.
export const isJsSpace = (c: number): boolean =>
  c === 9 ||
  c === 10 ||
  c === 11 ||
  c === 12 ||
  c === 13 ||
  c === 32 ||
  c === 0xa0 ||
  c === 0x1680 ||
  (c >= 0x2000 && c <= 0x200a) ||
  c === 0x2028 ||
  c === 0x2029 ||
  c === 0x202f ||
  c === 0x205f ||
  c === 0x3000 ||
  c === 0xfeff

const lower = (c: number): number => (c >= 65 && c <= 90 ? c + 32 : c)

// Case-insensitive (ASCII) prefix test; `p` must be lowercase.
function startsFold(s: string, i: number, p: string): boolean {
  if (i + p.length > s.length) return false
  for (let k = 0; k < p.length; k++) if (lower(s.charCodeAt(i + k)) !== p.charCodeAt(k)) return false
  return true
}

// End of the maximal run of `inClass` characters containing or starting at
// `i`, memoised for the run last seen. A query at a character outside the class
// returns `i` (an empty run).
function runCache(s: string, inClass: (c: number) => boolean): (i: number) => number {
  let start = -1
  let end = -1
  return (i) => {
    if (i >= start && i < end) return end
    if (!inClass(s.charCodeAt(i))) return i
    let e = i
    while (e < s.length && inClass(s.charCodeAt(e))) e++
    start = i
    end = e
    return e
  }
}

// First index >= i where `pred` holds (s.length if none), memoised: the answer
// holds for every index between the query and the hit.
function nextCache(s: string, pred: (s: string, k: number) => boolean): (i: number) => number {
  let at = -1
  let from = -1
  return (i) => {
    if (i <= at && i >= from) return at
    let k = i
    while (k < s.length && !pred(s, k)) k++
    from = i
    at = k
    return k
  }
}

const BARE_EXCLUDED = new Set([39, 34, 96, 40, 41, 91, 93, 123, 125, 46, 59, 44])
const bareClass = (c: number): boolean => !isJsSpace(c) && !BARE_EXCLUDED.has(c)
const quotedClass = (c: number): boolean => !isJsSpace(c) && c !== 39 && c !== 34
const OPERATORS = new Set([45, 43, 42, 47, 37, 46, 91, 40])
const isBlank = (c: number): boolean => c === 32 || c === 9

const REFERENCE_SUFFIXES = ['_file', '_path', '_dir', '_url']

// Does the word run s[i, j) hold a credential keyword: `_KEY` after an
// underscore, SECRET, TOKEN, PASSWORD, PASSWD, CREDENTIAL(S), or `_PAT` not
// followed by a letter. A keyword fits inside the run, since all its characters
// are word characters; the first character picks the one to compare.
function nameHasKeyword(s: string, i: number, j: number): boolean {
  for (let p = i; p < j; p++) {
    switch (lower(s.charCodeAt(p))) {
      case 115: // s
        if (p + 6 <= j && startsFold(s, p, 'secret')) return true
        break
      case 116: // t
        if (p + 5 <= j && startsFold(s, p, 'token')) return true
        break
      case 112: // p
        if (p + 8 <= j && startsFold(s, p, 'password')) return true
        if (p + 6 <= j && startsFold(s, p, 'passwd')) return true
        break
      case 99: // c
        if (p + 10 <= j && startsFold(s, p, 'credential')) return true
        break
      case 107: // k
        if (p > i && s.charCodeAt(p - 1) === 95 && p + 3 <= j && startsFold(s, p, 'key')) return true
        break
      case 95: // _
        if (p + 4 <= j && startsFold(s, p, '_pat') && !isLetter(p + 4 < s.length ? s.charCodeAt(p + 4) : -1)) return true
        break
    }
  }
  return false
}

function endsFold(s: string, i: number, j: number, suffix: string): boolean {
  return j - i >= suffix.length && startsFold(s, j - suffix.length, suffix)
}

// generic-key-env-assignment. The name is always the whole word run that
// starts at a word boundary, provided the run holds a keyword. Neither value
// branch can usefully backtrack: each value is a maximal run that must end at
// a fixed set of characters.
export const genericKeyEnvSpans: SpanScanner = (s) => {
  const out: Span[] = []
  const n = s.length
  const bareEnd = runCache(s, bareClass)
  const quotedEnd = runCache(s, quotedClass)
  const nextDigit = nextCache(s, (t, k) => isDigit(t.charCodeAt(k)))
  const nextDigitQuoted = nextCache(s, (t, k) => isDigit(t.charCodeAt(k)))
  const nextInterpolation = nextCache(s, (t, k) => t.charCodeAt(k) === 36 && t.charCodeAt(k + 1) === 123)
  for (let i = 0; i < n; ) {
    if (!isWord(s.charCodeAt(i)) || (i > 0 && isWord(s.charCodeAt(i - 1)))) {
      i++
      continue
    }
    let j = i
    while (j < n && isWord(s.charCodeAt(j))) j++
    if (!nameHasKeyword(s, i, j) || REFERENCE_SUFFIXES.some((suffix) => endsFold(s, i, j, suffix))) {
      i = j
      continue
    }
    let k = j
    while (k < n && isBlank(s.charCodeAt(k))) k++
    if (k >= n || s.charCodeAt(k) !== 61) {
      i = j
      continue
    }
    let v = k + 1
    while (v < n && isBlank(s.charCodeAt(v))) v++
    if (v >= n) {
      i = j
      continue
    }
    let end = -1
    const q = s.charCodeAt(v)
    if (q === 39 || q === 34) {
      const a = v + 1
      if (a < n && s.charCodeAt(a) !== 36 && !startsFold(s, a, '[redacted:')) {
        const e = quotedEnd(a)
        if (nextInterpolation(a) >= e && nextDigitQuoted(a) < e && e - a >= 16 && e < n && s.charCodeAt(e) === q) {
          let t = e + 1
          while (t < n && isBlank(s.charCodeAt(t))) t++
          if (t >= n || !OPERATORS.has(s.charCodeAt(t))) end = e + 1
        }
      }
    } else if (q !== 36) {
      const e = bareEnd(v)
      if (nextDigit(v) < e && e - v >= 16) {
        const c = e < n ? s.charCodeAt(e) : -1
        if (c === -1 || isJsSpace(c) || c === 59 || c === 44 || c === 39 || c === 34 || c === 96) end = e
      }
    }
    if (end > 0) {
      out.push({ start: i, end })
      i = end
      continue
    }
    i = j
  }
  return out
}

// bearer-header. The digit lookahead and the {20,} floor both act on the one
// maximal token run after the whitespace.
const isBearerToken = (c: number): boolean => isWord(c) || c === 46 || c === 126 || c === 43 || c === 47 || c === 45

export const bearerSpans: SpanScanner = (s) => {
  const out: Span[] = []
  const n = s.length
  let runStart = -1
  let runEnd = -1
  let lastDigit = -1
  for (let i = 0; i + 6 <= n; ) {
    if (!startsFold(s, i, 'bearer') || (i > 0 && isWord(s.charCodeAt(i - 1)))) {
      i++
      continue
    }
    let sp = i + 6
    while (sp < n && isJsSpace(s.charCodeAt(sp))) sp++
    if (sp === i + 6) {
      i++
      continue
    }
    if (!(sp >= runStart && sp < runEnd)) {
      runStart = sp
      runEnd = sp
      lastDigit = -1
      while (runEnd < n && isBearerToken(s.charCodeAt(runEnd))) {
        if (isDigit(s.charCodeAt(runEnd))) lastDigit = runEnd
        runEnd++
      }
    }
    if (lastDigit >= sp && runEnd - sp >= 20) {
      let e = runEnd
      while (e < n && s.charCodeAt(e) === 61) e++
      out.push({ start: i, end: e })
      i = e
      continue
    }
    i++
  }
  return out
}

// jwt. The first two segments must be maximal runs, each followed by a dot.
// The third backs off only to the last word boundary inside its run.
const isJwtSegment = (c: number): boolean => isWord(c) || c === 45

export const jwtSpans: SpanScanner = (s) => {
  const out: Span[] = []
  const n = s.length
  // Run ends for the whole string, built once on the first candidate, so no
  // pattern of candidate starts can make a run be rescanned.
  let ends: Int32Array | null = null
  const segmentEnd = (i: number): number => {
    if (ends === null) {
      ends = new Int32Array(n + 1)
      ends[n] = n
      for (let k = n - 1; k >= 0; k--) ends[k] = isJwtSegment(s.charCodeAt(k)) ? ends[k + 1] : k
    }
    return ends[i]
  }
  // Candidates inside one run share their third segment, so the back-off over
  // its trailing hyphens is done once per segment.
  let thirdStart = -1
  let thirdEnd = -1
  for (let i = 0; i + 3 <= n; ) {
    if (s.charCodeAt(i) !== 101 || s.charCodeAt(i + 1) !== 121 || s.charCodeAt(i + 2) !== 74 || (i > 0 && isWord(s.charCodeAt(i - 1)))) {
      i++
      continue
    }
    const e1 = segmentEnd(i + 3)
    if (e1 > i + 3 && s.charCodeAt(e1) === 46) {
      const e2 = segmentEnd(e1 + 1)
      if (e2 > e1 + 1 && s.charCodeAt(e2) === 46) {
        const a3 = e2 + 1
        if (a3 !== thirdStart) {
          // \b after the greedy third segment: back off to the last
          // word/non-word boundary inside it.
          let e3 = segmentEnd(a3)
          while (e3 > a3 && isWord(s.charCodeAt(e3 - 1)) === (e3 < n && isWord(s.charCodeAt(e3)))) e3--
          thirdStart = a3
          thirdEnd = e3
        }
        if (thirdEnd > a3) {
          out.push({ start: i, end: thirdEnd })
          i = thirdEnd
          continue
        }
      }
    }
    i++
  }
  return out
}

// private-key-block: -----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----
const isUpperOrSpace = (c: number): boolean => (c >= 65 && c <= 90) || c === 32
const PEM_TAIL = 'PRIVATE KEY-----'

// A header's `PRIVATE KEY-----` can only start 11 characters before the end of
// the [A-Z ] run, because "PRIVATE KEY" is inside the run and "-----" ends it.
// Returns the header's end, or -1.
function pemHeaderEnd(s: string, from: number, runEnd: number): number {
  const q = runEnd - 11
  return q >= from && s.startsWith(PEM_TAIL, q) ? q + PEM_TAIL.length : -1
}

export interface PemScan {
  spans: Span[]
  // Start of the first BEGIN header that no END header follows, or -1. Its
  // block never closes, so everything from there to the end of the text is
  // key material that the rule did not match.
  unclosedFrom: number
}

export function pemScan(s: string): PemScan {
  const spans: Span[] = []
  const headerRun = runCache(s, isUpperOrSpace)
  // Valid END headers, ascending, each with the end of its match.
  const ends: Span[] = []
  for (let p = s.indexOf('-----END '); p !== -1; p = s.indexOf('-----END ', p + 1)) {
    const he = pemHeaderEnd(s, p + 9, headerRun(p + 9))
    if (he > 0) ends.push({ start: p, end: he })
  }
  let ei = 0
  for (let p = s.indexOf('-----BEGIN '); p !== -1; ) {
    const he = pemHeaderEnd(s, p + 11, headerRun(p + 11))
    if (he < 0) {
      p = s.indexOf('-----BEGIN ', p + 1)
      continue
    }
    while (ei < ends.length && ends[ei].start < he) ei++
    // No END after this BEGIN, so none after any later one either.
    if (ei >= ends.length) return { spans, unclosedFrom: p }
    const end = ends[ei].end
    spans.push({ start: p, end })
    p = s.indexOf('-----BEGIN ', end)
  }
  return { spans, unclosedFrom: -1 }
}

export const pemSpans: SpanScanner = (s) => pemScan(s).spans
