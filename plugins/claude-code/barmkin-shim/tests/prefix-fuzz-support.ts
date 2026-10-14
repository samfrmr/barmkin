// The seeded fuzz behind tests/scanned-prefix-fuzz-*.test.ts: plant a secret,
// more than half of the time straddling the 12 KiB mark, and look for any
// 12-character piece of it in what would be shown. A naive slice at 12 KiB is
// the control: if it did not leak, the corpus would prove nothing.
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactInEitherView } from '../hooks/lib/redaction'
import { scannedPrefix, PREFIX_KEEP_CHARS } from '../hooks/lib/scanned-prefix'
import { ALNUM, B64, UPPER_DIGITS, pemHeader, randOf, type Rand } from './fuzz-support'

const KEEP = PREFIX_KEEP_CHARS

interface Planted {
  // The text to plant, on its own line or between spaces.
  text: string
  // Strings of which no 12-character piece may appear in what is shown.
  secrets: string[]
}

const WORDS = ['alpha', 'build', 'cache', 'deploy', 'error', 'fetch', 'graph', 'handle', 'index', 'job', 'kernel', 'log', 'merge', 'node', 'output', 'parse', 'queue', 'route', 'step', 'test', 'user', 'value', 'worker']

function plantAws(r: Rand): Planted {
  const key = 'AKIA' + r.chars(UPPER_DIGITS, 16)
  return { text: 'aws_access_key_id ' + key, secrets: [key] }
}
function plantGithub(r: Rand): Planted {
  const token = 'ghp_' + r.chars(ALNUM, 36)
  return { text: 'remote: ' + token, secrets: [token] }
}
function plantAnthropic(r: Rand): Planted {
  const key = 'sk-ant-api03-' + r.chars(ALNUM + '_-', 40) + r.chars(ALNUM, 4)
  return { text: 'ANTHROPIC ' + key, secrets: [key] }
}
function plantJwtBearer(r: Rand): Planted {
  const jwt = 'eyJ' + r.chars(ALNUM, 20) + '.eyJ' + r.chars(ALNUM, 30) + '.' + r.chars(ALNUM + '_-', 30) + r.chars(ALNUM, 2)
  return { text: 'Authorization: Bearer ' + jwt, secrets: [jwt] }
}
function plantEnvAssignment(r: Rand): Planted {
  const value = r.chars(ALNUM, 18) + '7'
  return { text: 'export DB_PASSWORD=' + value, secrets: [value] }
}
function plantUrlUserinfo(r: Rand): Planted {
  const password = r.chars(ALNUM, 14)
  return { text: 'postgres://app:' + password + '@db.internal:5432/main', secrets: [password] }
}
function plantPem(r: Rand): Planted {
  const lines = Array.from({ length: r.int(2, 62) }, () => r.chars(B64, 64))
  return { text: pemHeader('BEGIN', 'RSA ') + '\n' + lines.join('\n') + '\n' + pemHeader('END', 'RSA '), secrets: lines }
}
function plantZeroWidthSplit(r: Rand): Planted {
  const key = 'AKIA' + r.chars(UPPER_DIGITS, 16)
  const at = r.int(1, key.length - 1)
  return { text: 'key ' + key.slice(0, at) + '\u200b' + key.slice(at), secrets: [key] }
}
function plantPemInOneLine(r: Rand): Planted {
  // A key pasted with spaces for newlines is not a block: only its pieces count.
  const body = r.chars(B64, 80)
  return { text: 'TLS_KEY_PASSWORD="' + body + '"' + ' 9', secrets: [body] }
}

const SHAPES = [plantAws, plantGithub, plantAnthropic, plantJwtBearer, plantEnvAssignment, plantUrlUserinfo, plantPem, plantZeroWidthSplit, plantPemInOneLine]
// Short shapes that can stand as decoys around the planted one.
const DECOYS = [plantAws, plantGithub, plantJwtBearer, plantEnvAssignment, plantUrlUserinfo]

// Filler text of exact length, cut from one pool of word lines (or the same
// text on one line), so a fuzz trial spends its time on the cut, not on
// building text.
const POOL = (() => {
  const r = randOf(123456)
  let out = ''
  while (out.length < 700 * 1024) {
    out += Array.from({ length: r.int(3, 16) }, () => r.pick(WORDS) + (r.next() < 0.2 ? '_' + r.int(0, 999) : '')).join(' ') + '\n'
  }
  return { lines: out, flat: out.replace(/\n/g, ' ') }
})()

export function filler(r: Rand, length: number, oneLine: boolean): string {
  const pool = oneLine ? POOL.flat : POOL.lines
  const at = r.int(0, pool.length - length - 1)
  return pool.slice(at, at + length)
}

// An exact-length filler that ends where a planted line can start: on a line
// boundary (multi-line) or after a space (one line).
export function fillerTo(r: Rand, length: number, oneLine: boolean): string {
  if (length <= 0) return ''
  return filler(r, length - 1, oneLine) + (oneLine ? ' ' : '\n')
}

interface Trial {
  text: string
  secrets: string[]
  straddles: boolean
}

function buildTrial(r: Rand, oneLine: boolean): Trial {
  const shape = r.pick(SHAPES)(r)
  const decoys = Array.from({ length: r.int(0, 5) }, () => r.pick(DECOYS)(r))
  const straddles = r.next() < 0.55
  // The planted text starts at `start`; when it straddles, the mark falls inside it.
  const start = straddles ? KEEP - r.int(1, shape.text.length - 1) : r.int(0, 2 * KEEP)
  // Rule-heavy neighbours before the planted secret, ahead of the filler.
  const lead = decoys.map((d) => d.text + (oneLine ? ' ' : '\n')).join('')
  const useDecoys = lead.length > 0 && lead.length + 2 < start
  let text = (useDecoys ? lead : '') + fillerTo(r, start - (useDecoys ? lead.length : 0), oneLine)
  text += shape.text + (oneLine ? ' ' : '\n')
  text += filler(r, 20 * 1024 + r.int(0, 4096), oneLine)
  return {
    text,
    secrets: [...shape.secrets, ...(useDecoys ? decoys.flatMap((d) => d.secrets) : [])],
    straddles: start < KEEP && KEEP < start + shape.text.length,
  }
}

// True when some 12-character piece of a secret appears in the text.
export function leaks(shown: string, secrets: string[]): boolean {
  for (const secret of secrets) {
    const stride = secret.length > 100 ? 6 : 1
    for (let i = 0; i + 12 <= secret.length; i += stride) {
      if (shown.includes(secret.slice(i, i + 12))) return true
    }
  }
  return false
}

export interface FuzzStats {
  trials: number
  straddling: number
  leaks: number
  naiveLeaks: number
  controls: number
  withheld: number
}

export function runFuzz(seed: number, trials: number, oneLine: boolean, controlEvery = 1): FuzzStats {
  const r = randOf(seed)
  const stats: FuzzStats = { trials: 0, straddling: 0, leaks: 0, naiveLeaks: 0, controls: 0, withheld: 0 }
  for (let i = 0; i < trials; i++) {
    const trial = buildTrial(r, oneLine)
    stats.trials++
    if (trial.straddles) stats.straddling++
    const prefix = scannedPrefix(trial.text, REDACTION_RULES, {})
    if (prefix === null) stats.withheld++
    else if (leaks(prefix.shown, trial.secrets)) {
      stats.leaks++
      if (stats.leaks === 1) throw new Error('leak at seed ' + seed + ' trial ' + i + ' cut ' + prefix.cut + ' secrets ' + JSON.stringify(trial.secrets.map((s) => s.slice(0, 20))))
    }
    // Control: redact the same text cut at 12 KiB with no regard for matches.
    if (trial.straddles && i % controlEvery === 0) {
      stats.controls++
      if (leaks(redactInEitherView(trial.text.slice(0, KEEP), REDACTION_RULES, {}).text, trial.secrets)) stats.naiveLeaks++
    }
  }
  return stats
}

