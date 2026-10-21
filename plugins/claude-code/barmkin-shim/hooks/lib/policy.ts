// The root policy: one YAML file at a fixed path under /etc that root writes
// and both shims read (this Claude Code shim, and the OpenCode shim through
// shims/opencode/src/lib.ts). On the managed seats /etc is root's and AppArmor
// keeps a sandbox's root out of it, so the file is the trust boundary: there is
// no other path, no environment override and no user-writable source.
//
// The policy can only add. Its four lists add redaction rules, injection
// phrases for the screen's local heuristic, secret paths that raise the
// sensitive leg, and outward-effect shell commands for the shell-outward egress
// class. Each is appended after the built-in list it extends, which the policy
// cannot name, reorder, remove or replace: there is no allow, disable or
// override key, and an unknown key makes the whole file invalid. The taint,
// the egress decision, the monitor peer, the managed gate and the sticky legs
// are not in the schema at all.
//
// Host-neutral: no `$`, no Node. Each shim reads the file its own way (see
// PolicyRead) and hands the result to policyFromRead.

import { REDACTION_RULES, type RedactionRule } from './redaction-rules'
import { EGRESS_CLASSES, widenShellOutward, type EgressClass } from './egress'

// The one path either shim reads.
export const POLICY_PATH = '/etc/barmkin/policy.yaml'

export const POLICY_VERSION = 1

// Bounds on the file and on what it may ask the shims to run. A pattern runs on
// every string its surface scans (up to 256 KiB for redaction), so each is held
// to a syntax with no backtracking blow-up and a bounded cost (checkPattern).
export const MAX_POLICY_BYTES = 64 * 1024
export const MAX_ENTRIES_PER_LIST = 32
export const MAX_PATTERN_CHARS = 256
export const MAX_EXAMPLE_CHARS = 1024
export const MAX_REPEAT = 256
// A loose bound on the steps one pattern may take from a start position: the
// most characters it can match, times its backtracking paths (the product of
// each repetition's span, max - min + 1, and each alternation's branch count).
// A list's patterns together have a bound too. tests/policy-budget.test.ts runs
// the costliest redaction list the bounds allow against text built to slow it,
// and holds it to the built-in rules' budget of 800 ms per MiB.
export const MAX_PATTERN_COST = 256
export const MAX_LIST_COST = 512
const MAX_GROUP_DEPTH = 4

export type PolicyList = 'redaction' | 'injection_phrases' | 'secret_paths' | 'outward_commands'
export const POLICY_LISTS: readonly PolicyList[] = ['redaction', 'injection_phrases', 'secret_paths', 'outward_commands']

// The built-in lists with the policy's additions after them.
export interface ActivePolicy {
  // Every built-in rule, in order, then the policy's.
  readonly redactionRules: readonly RedactionRule[]
  // The policy's injection phrases; heuristicInjectionScore keeps its own.
  readonly injectionPatterns: readonly RegExp[]
  // The policy's secret paths; touchesSecretPath keeps its own.
  readonly secretPathPatterns: readonly RegExp[]
  // EGRESS_CLASSES with shell-outward widened by the policy's commands.
  readonly egressClasses: readonly EgressClass[]
  // The names the policy added, per list, for the status surfaces.
  readonly added: Readonly<Record<PolicyList, readonly string[]>>
}

// How a shim's read of POLICY_PATH came out. `refused` is a file that exists but
// was not read: a symbolic link, the wrong owner or mode, too large, or an error.
export type PolicyRead = { kind: 'absent' } | { kind: 'file'; text: string } | { kind: 'refused'; reason: string }

// What the shim enforces. `absent` and `loaded` carry the policy to use; an
// `invalid` policy is never partly applied, and the shim denies every step it
// guards with the monitor until root fixes the file.
export type PolicyLoad =
  | { state: 'absent'; policy: ActivePolicy }
  | { state: 'loaded'; policy: ActivePolicy }
  | { state: 'invalid'; reason: string }

export class PolicyError extends Error {}

// ---------------------------------------------------------------------------
// The YAML subset. The schema is flat, so the parser takes only what it needs:
// top-level `key: scalar` and `key:` followed by a block list of flat
// `- key: scalar` mappings, `[]` for an empty list, plain, single-quoted and
// double-quoted scalars, and comments. Anchors, aliases, tags, flow
// collections, block scalars and more than one document are refused rather
// than guessed at, as are YAML 1.1 words (yes, no, on, off, null, ~) that
// parsers read differently.
// ---------------------------------------------------------------------------

type Scalar = string | number | boolean
interface Located<T> {
  value: T
  line: number
}
type Item = Map<string, Located<Scalar>>
type Doc = Map<string, Located<Scalar | Item[]>>

function fail(line: number, message: string): never {
  throw new PolicyError('line ' + line + ': ' + message)
}

const KEY = /^([a-z][a-z0-9_]*):(?=\s|$)/
const AMBIGUOUS = /^(?:y|Y|yes|Yes|YES|n|N|no|No|NO|on|On|ON|off|Off|OFF|null|Null|NULL|~|True|TRUE|False|FALSE)$/
const PLAIN_START_REFUSED = /^[[\]{}&*!|>'"%@`#,?:-]/

// Reads one scalar starting at `rest` (the text after `key:`), and checks that
// only a comment follows it.
function parseScalar(rest: string, line: number): Scalar | 'empty-list' {
  const text = rest.trimStart()
  if (text === '' || text.startsWith('#')) fail(line, 'a value is needed here (use [] for an empty list)')
  let value: string
  let after: string
  if (text[0] === "'") {
    let out = ''
    let i = 1
    for (;;) {
      if (i >= text.length) fail(line, 'a single-quoted value is not closed on its line')
      if (text[i] === "'") {
        if (text[i + 1] === "'") {
          out += "'"
          i += 2
          continue
        }
        break
      }
      out += text[i++]
    }
    value = out
    after = text.slice(i + 1)
  } else if (text[0] === '"') {
    let out = ''
    let i = 1
    for (;;) {
      if (i >= text.length) fail(line, 'a double-quoted value is not closed on its line')
      const c = text[i]
      if (c === '"') break
      if (c === '\\') {
        const e = text[i + 1]
        const mapped = e === '\\' ? '\\' : e === '"' ? '"' : e === 'n' ? '\n' : e === 't' ? '\t' : null
        if (mapped === null) fail(line, 'a double-quoted value may only escape \\\\, \\", \\n and \\t (single quotes need no escapes)')
        out += mapped
        i += 2
        continue
      }
      out += c
      i++
    }
    value = out
    after = text.slice(i + 1)
  } else {
    if (text.startsWith('[]')) {
      after = text.slice(2)
      if (after.trim() !== '' && !/^\s+#/.test(after)) fail(line, 'only [] is accepted as a flow list')
      return 'empty-list'
    }
    if (PLAIN_START_REFUSED.test(text)) fail(line, 'quote a value that starts with ' + JSON.stringify(text[0]))
    const comment = text.search(/\s#/)
    value = (comment === -1 ? text : text.slice(0, comment)).trimEnd()
    if (/:\s|:$/.test(value)) fail(line, 'quote a value that contains ": "')
    if (AMBIGUOUS.test(value)) fail(line, 'quote ' + JSON.stringify(value) + ' or use true/false: YAML parsers disagree on it')
    if (value === 'true') return true
    if (value === 'false') return false
    if (/^-?[0-9]+$/.test(value)) return Number(value)
    return value
  }
  if (after.trim() !== '' && !/^\s+#/.test(after)) fail(line, 'unexpected text after a quoted value')
  return value
}

function parseYamlSubset(text: string): Doc {
  const source = text.startsWith('﻿') ? text.slice(1) : text
  const lines = source.split(/\r?\n/)
  const doc: Doc = new Map()
  let list: { items: Item[]; dash: number; keyCol: number } | null = null
  let item: Item | null = null
  let sawContent = false

  for (let n = 0; n < lines.length; n++) {
    const line = n + 1
    const raw = lines[n]
    if (/[\u0000-\u0008\u000b-\u001f\u007f]/.test(raw)) fail(line, 'control characters are not allowed')
    if (raw.includes('\t')) fail(line, 'tabs are not allowed; indent with spaces')
    const body = raw.trimStart()
    if (body === '' || body.startsWith('#')) continue
    const indent = raw.length - body.length

    if (!sawContent && indent === 0 && /^---\s*(?:#.*)?$/.test(body)) {
      sawContent = true
      continue
    }
    sawContent = true
    if (/^(?:---|\.\.\.)(?:\s|$)/.test(body)) fail(line, 'the policy is a single YAML document')

    if (body.startsWith('- ') || body === '-') {
      if (!list) fail(line, 'a list item is only allowed under redaction, injection_phrases, secret_paths or outward_commands')
      if (list.items.length > 0 && indent !== list.dash) fail(line, 'list items must line up')
      const inner = body.slice(1)
      const keyText = inner.trimStart()
      if (keyText === '' || !KEY.test(keyText)) fail(line, 'each list item is a mapping: "- name: ..."')
      list.dash = indent
      list.keyCol = indent + 1 + (inner.length - keyText.length)
      item = new Map()
      list.items.push(item)
      addKey(item, keyText, line)
      continue
    }

    if (indent === 0) {
      list = null
      item = null
      const m = KEY.exec(body)
      if (!m) fail(line, 'expected "key: value" at the top level')
      const key = m[1]
      if (doc.has(key)) fail(line, 'duplicate key ' + JSON.stringify(key))
      const rest = body.slice(m[0].length)
      if (rest.trim() === '' || /^\s+#/.test(rest)) {
        const items: Item[] = []
        doc.set(key, { value: items, line })
        list = { items, dash: -1, keyCol: -1 }
        continue
      }
      const scalar = parseScalar(rest, line)
      doc.set(key, { value: scalar === 'empty-list' ? [] : scalar, line })
      continue
    }

    if (!item || !list || indent !== list.keyCol) fail(line, 'unexpected indentation')
    addKey(item, body, line)
  }

  for (const [key, entry] of doc) {
    if (Array.isArray(entry.value) && entry.value.length === 0 && !isEmptyListLiteral(lines[entry.line - 1])) {
      fail(entry.line, JSON.stringify(key) + ' has no value (use [] for an empty list)')
    }
  }
  return doc
}

function isEmptyListLiteral(raw: string): boolean {
  return /:\s*\[\]\s*(?:#.*)?$/.test(raw)
}

function addKey(item: Item, text: string, line: number): void {
  const m = KEY.exec(text)
  if (!m) fail(line, 'expected "key: value"')
  const key = m[1]
  if (item.has(key)) fail(line, 'duplicate key ' + JSON.stringify(key))
  const scalar = parseScalar(text.slice(m[0].length), line)
  if (scalar === 'empty-list') fail(line, JSON.stringify(key) + ' takes a single value, not a list')
  item.set(key, { value: scalar, line })
}

// ---------------------------------------------------------------------------
// Patterns. A policy pattern is a JavaScript regular expression in a narrow
// syntax: literals, `.`, the \d \w \s classes and their negations, bracket
// classes, ^ $ \b \B, groups and alternation, and repetition with an upper
// bound. No backreferences, lookaround, named groups, Unicode escapes or
// unbounded repetition (`*`, `+`, `{n,}`), and a group cannot be repeated, so
// the work a pattern does from each start position is bounded.
// It must match at least one character, so it never matches empty text.
// Its cost (checkPattern) is bounded, and so is the sum over a list.
// ---------------------------------------------------------------------------

const CLASS_ESCAPES = 'dDwWsS'
const CONTROL_ESCAPES: Record<string, true> = { t: true, n: true, r: true }
const SYNTAX_CHARS = '^$\\.*+?()[]{}|/'

interface Scan {
  src: string
  i: number
  cost: number
}

interface Piece {
  minLen: number
  maxLen: number
  repeatable: boolean
}

interface Span {
  minLen: number
  maxLen: number
}

function patternError(message: string): never {
  throw new PolicyError(message)
}

// Returns the pattern's cost, or throws a PolicyError saying what it refused.
export function checkPattern(src: string): number {
  if (src.length === 0) patternError('the pattern is empty')
  if (src.length > MAX_PATTERN_CHARS) patternError('the pattern is longer than ' + MAX_PATTERN_CHARS + ' characters')
  const scan: Scan = { src, i: 0, cost: 1 }
  const span = parseAlternation(scan, 0)
  if (scan.i !== src.length) patternError('unmatched ")" at offset ' + scan.i)
  if (span.minLen < 1) patternError('the pattern can match empty text')
  const cost = scan.cost * span.maxLen
  if (cost > MAX_PATTERN_COST) {
    patternError('the pattern costs ' + cost + ' (the limit is ' + MAX_PATTERN_COST + '): shorten it, or narrow its repetition ranges or alternatives')
  }
  return cost
}

function parseAlternation(scan: Scan, depth: number): Span {
  let branches = 1
  const span = parseSequence(scan, depth)
  while (scan.src[scan.i] === '|') {
    scan.i++
    branches++
    const next = parseSequence(scan, depth)
    span.minLen = Math.min(span.minLen, next.minLen)
    span.maxLen = Math.max(span.maxLen, next.maxLen)
  }
  scan.cost *= branches
  return span
}

function parseSequence(scan: Scan, depth: number): Span {
  const span: Span = { minLen: 0, maxLen: 0 }
  while (scan.i < scan.src.length && scan.src[scan.i] !== '|' && scan.src[scan.i] !== ')') {
    const at = scan.i
    const piece = parseAtom(scan, depth)
    const repeat = parseRepeat(scan)
    if (repeat) {
      if (!piece.repeatable) patternError('offset ' + at + ': only a single character, class or escape may be repeated (not a group or an assertion)')
      scan.cost *= repeat.max - repeat.min + 1
      span.minLen += piece.minLen * repeat.min
      span.maxLen += piece.maxLen * repeat.max
    } else {
      span.minLen += piece.minLen
      span.maxLen += piece.maxLen
    }
  }
  return span
}

function parseAtom(scan: Scan, depth: number): Piece {
  const { src } = scan
  const c = src[scan.i]
  if (c === '(') {
    if (depth + 1 > MAX_GROUP_DEPTH) patternError('groups nest deeper than ' + MAX_GROUP_DEPTH)
    scan.i++
    if (src[scan.i] === '?') {
      if (src[scan.i + 1] !== ':') patternError('offset ' + scan.i + ': only (...) and (?:...) groups are accepted (no lookaround, named groups or flags)')
      scan.i += 2
    }
    const span = parseAlternation(scan, depth + 1)
    if (src[scan.i] !== ')') patternError('a group is not closed')
    scan.i++
    return { ...span, repeatable: false }
  }
  if (c === '[') return parseClass(scan)
  if (c === '.') {
    scan.i++
    return { minLen: 1, maxLen: 1, repeatable: true }
  }
  if (c === '^' || c === '$') {
    scan.i++
    return { minLen: 0, maxLen: 0, repeatable: false }
  }
  if (c === '\\') {
    const e = src[scan.i + 1]
    if (e === undefined) patternError('the pattern ends in a backslash')
    scan.i += 2
    if (e === 'b' || e === 'B') return { minLen: 0, maxLen: 0, repeatable: false }
    if (CLASS_ESCAPES.includes(e) || CONTROL_ESCAPES[e] || SYNTAX_CHARS.includes(e)) return { minLen: 1, maxLen: 1, repeatable: true }
    patternError('offset ' + (scan.i - 2) + ': the escape \\' + e + ' is not accepted (no backreferences or Unicode, hex or control escapes)')
  }
  if ('*+?{'.includes(c)) patternError('offset ' + scan.i + ': ' + JSON.stringify(c) + ' has nothing to repeat (escape it to match it)')
  if (c === '}' || c === ']') patternError('offset ' + scan.i + ': escape ' + JSON.stringify(c) + ' to match it')
  scan.i++
  return { minLen: 1, maxLen: 1, repeatable: true }
}

function parseRepeat(scan: Scan): { min: number; max: number } | null {
  const { src } = scan
  const c = src[scan.i]
  let repeat: { min: number; max: number }
  if (c === '?') {
    scan.i++
    repeat = { min: 0, max: 1 }
  } else if (c === '*' || c === '+') {
    patternError('offset ' + scan.i + ': ' + JSON.stringify(c) + ' repeats without bound; give it an upper bound, as {0,' + MAX_REPEAT + '} or {1,' + MAX_REPEAT + '}')
  } else if (c === '{') {
    const m = /^\{([0-9]{1,4})(?:(,)([0-9]{1,4})?)?\}/.exec(src.slice(scan.i))
    if (!m) patternError('offset ' + scan.i + ': a repetition is {n} or {n,m}')
    const min = Number(m[1])
    if (m[2] && m[3] === undefined) patternError('offset ' + scan.i + ': {' + min + ',} repeats without bound; give it an upper bound')
    const max = m[3] === undefined ? min : Number(m[3])
    if (max < min) patternError('offset ' + scan.i + ': {' + min + ',' + max + '} is out of order')
    if (max > MAX_REPEAT) patternError('offset ' + scan.i + ': a repetition may not exceed ' + MAX_REPEAT)
    if (max === 0) patternError('offset ' + scan.i + ': a repetition of zero matches nothing')
    scan.i += m[0].length
    repeat = { min, max }
  } else {
    return null
  }
  if (src[scan.i] === '?') scan.i++
  const after = src[scan.i]
  if (after !== undefined && '?*+{'.includes(after)) patternError('offset ' + scan.i + ': a repetition cannot itself be repeated')
  return repeat
}

function parseClass(scan: Scan): Piece {
  const { src } = scan
  scan.i++
  if (src[scan.i] === '^') scan.i++
  let items = 0
  for (;;) {
    const c = src[scan.i]
    if (c === undefined) patternError('a [...] class is not closed')
    if (c === ']') break
    const low = classChar(scan, true)
    items++
    if (src[scan.i] === '-' && src[scan.i + 1] !== ']' && src[scan.i + 1] !== undefined) {
      scan.i++
      const high = classChar(scan, false)
      if (low === null || high === null) patternError('offset ' + scan.i + ': a range needs a single character at each end')
      if (high < low) patternError('offset ' + scan.i + ': the range is out of order')
    }
  }
  if (items === 0) patternError('a [...] class is empty')
  scan.i++
  return { minLen: 1, maxLen: 1, repeatable: true }
}

// One class member: its code point, or null for a class escape (\d, \w, ...).
function classChar(scan: Scan, allowClassEscape: boolean): number | null {
  const { src } = scan
  const c = src[scan.i]
  if (c === '[') patternError('offset ' + scan.i + ': escape "[" inside a class')
  if (c !== '\\') {
    const cp = src.codePointAt(scan.i) as number
    scan.i += cp > 0xffff ? 2 : 1
    return cp
  }
  const e = src[scan.i + 1]
  if (e === undefined) patternError('the pattern ends in a backslash')
  scan.i += 2
  if (CLASS_ESCAPES.includes(e)) {
    if (!allowClassEscape) patternError('offset ' + (scan.i - 2) + ': a range cannot end in \\' + e)
    return null
  }
  if (e === 't') return 9
  if (e === 'n') return 10
  if (e === 'r') return 13
  if (SYNTAX_CHARS.includes(e) || e === '-') return e.codePointAt(0) as number
  patternError('offset ' + (scan.i - 2) + ': the escape \\' + e + ' is not accepted inside a class')
}

// ---------------------------------------------------------------------------
// The schema.
// ---------------------------------------------------------------------------

interface EntrySpec {
  name: string
  pattern: RegExp
  example: string
  category?: string
}

interface PolicySpec {
  redaction: EntrySpec[]
  injection_phrases: EntrySpec[]
  secret_paths: EntrySpec[]
  outward_commands: EntrySpec[]
}

const TOP_KEYS = new Set<string>(['version', ...POLICY_LISTS])
const NAME = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/
const CATEGORY = /^[a-z][a-z0-9-]{0,31}$/
// Categories the redaction module writes itself.
const RESERVED_CATEGORIES = new Set(['oversized'])
const BUILTIN_RULE_NAMES = new Set(REDACTION_RULES.map((r) => r.name))

function entryKeys(list: PolicyList): readonly string[] {
  return list === 'redaction' ? ['name', 'category', 'pattern', 'example', 'ignore_case'] : ['name', 'pattern', 'example', 'ignore_case']
}

function str(item: Item, key: string, list: PolicyList, at: number): Located<string> {
  const entry = item.get(key)
  if (!entry) fail(at, list + ' entry needs "' + key + '"')
  if (typeof entry.value !== 'string') fail(entry.line, '"' + key + '" must be a string (quote it)')
  return entry as Located<string>
}

function validate(doc: Doc): PolicySpec {
  for (const [key, entry] of doc) {
    if (!TOP_KEYS.has(key)) fail(entry.line, 'unknown key ' + JSON.stringify(key) + '; the policy only adds to ' + POLICY_LISTS.join(', '))
  }
  const version = doc.get('version')
  if (!version) throw new PolicyError('"version: ' + POLICY_VERSION + '" is required')
  if (version.value !== POLICY_VERSION) fail(version.line, 'unsupported version ' + JSON.stringify(version.value) + ' (this shim reads version ' + POLICY_VERSION + ')')

  const names = new Set<string>()
  const spec: PolicySpec = { redaction: [], injection_phrases: [], secret_paths: [], outward_commands: [] }
  for (const list of POLICY_LISTS) {
    const entry = doc.get(list)
    if (!entry) continue
    if (!Array.isArray(entry.value)) fail(entry.line, JSON.stringify(list) + ' must be a list')
    if (entry.value.length > MAX_ENTRIES_PER_LIST) fail(entry.line, JSON.stringify(list) + ' has more than ' + MAX_ENTRIES_PER_LIST + ' entries')
    const allowed = entryKeys(list)
    let listCost = 0
    for (const item of entry.value) {
      const first = Math.min(...[...item.values()].map((v) => v.line))
      for (const [key, v] of item) {
        if (!allowed.includes(key)) fail(v.line, 'unknown key ' + JSON.stringify(key) + ' in a ' + list + ' entry (accepted: ' + allowed.join(', ') + ')')
      }
      const name = str(item, 'name', list, first)
      if (!NAME.test(name.value)) fail(name.line, 'a name is lowercase letters, digits and hyphens, at most 64 characters')
      if (names.has(name.value)) fail(name.line, 'the name ' + JSON.stringify(name.value) + ' is used twice')
      if (BUILTIN_RULE_NAMES.has(name.value)) fail(name.line, JSON.stringify(name.value) + ' is a built-in rule; the policy cannot replace one')
      names.add(name.value)

      const pattern = str(item, 'pattern', list, first)
      try {
        listCost += checkPattern(pattern.value)
      } catch (err) {
        fail(pattern.line, (err as Error).message)
      }
      if (listCost > MAX_LIST_COST) {
        fail(pattern.line, 'the ' + list + ' patterns together cost ' + listCost + ' (the limit is ' + MAX_LIST_COST + ')')
      }
      const ignoreCase = item.get('ignore_case')
      if (ignoreCase && typeof ignoreCase.value !== 'boolean') fail(ignoreCase.line, '"ignore_case" is true or false')
      const flags = 'u' + (ignoreCase?.value === true ? 'i' : '')
      let probe: RegExp
      try {
        probe = new RegExp(pattern.value, flags)
      } catch (err) {
        fail(pattern.line, 'the pattern does not compile: ' + (err as Error).message)
      }

      const example = str(item, 'example', list, first)
      if (example.value.length === 0 || example.value.length > MAX_EXAMPLE_CHARS) fail(example.line, 'an example is 1 to ' + MAX_EXAMPLE_CHARS + ' characters')
      if (!probe.test(example.value)) fail(example.line, 'the pattern does not match its example')

      const spec1: EntrySpec = { name: name.value, example: example.value, pattern: list === 'redaction' ? new RegExp(pattern.value, flags + 'g') : probe }
      if (list === 'redaction') {
        const category = str(item, 'category', list, first)
        if (!CATEGORY.test(category.value) || RESERVED_CATEGORIES.has(category.value)) {
          fail(category.line, 'a category is lowercase letters, digits and hyphens, at most 32 characters, and not "oversized"')
        }
        spec1.category = category.value
      }
      spec[list].push(spec1)
    }
  }
  return spec
}

// Parses and checks a policy file's text. Throws a PolicyError naming the line.
export function parsePolicy(text: string): ActivePolicy {
  if (text.length > MAX_POLICY_BYTES) throw new PolicyError('the file is larger than ' + MAX_POLICY_BYTES + ' bytes')
  return buildPolicy(validate(parseYamlSubset(text)))
}

function buildPolicy(spec: PolicySpec): ActivePolicy {
  const added: RedactionRule[] = spec.redaction.map((e) =>
    Object.freeze({ name: e.name, pattern: e.pattern, category: e.category as string, example: e.example }),
  )
  const names = (list: PolicyList) => Object.freeze(spec[list].map((e) => e.name))
  return Object.freeze({
    redactionRules: Object.freeze([...REDACTION_RULES, ...added]),
    injectionPatterns: Object.freeze(spec.injection_phrases.map((e) => e.pattern)),
    secretPathPatterns: Object.freeze(spec.secret_paths.map((e) => e.pattern)),
    egressClasses: Object.freeze(widenShellOutward(spec.outward_commands.map((e) => e.pattern), EGRESS_CLASSES)),
    added: Object.freeze({
      redaction: names('redaction'),
      injection_phrases: names('injection_phrases'),
      secret_paths: names('secret_paths'),
      outward_commands: names('outward_commands'),
    }),
  })
}

// The built-in lists alone: what a shim enforces when there is no policy file.
export const BUILTIN_POLICY: ActivePolicy = buildPolicy({ redaction: [], injection_phrases: [], secret_paths: [], outward_commands: [] })

// What a shim enforces, given how its read of POLICY_PATH came out.
export function policyFromRead(read: PolicyRead): PolicyLoad {
  if (read.kind === 'absent') return { state: 'absent', policy: BUILTIN_POLICY }
  if (read.kind === 'refused') return { state: 'invalid', reason: read.reason }
  try {
    return { state: 'loaded', policy: parsePolicy(read.text) }
  } catch (err) {
    return { state: 'invalid', reason: err instanceof PolicyError ? err.message : 'it could not be parsed' }
  }
}

// One line for the session-start log, the posture line and the status surface.
export function describePolicy(load: PolicyLoad): string {
  if (load.state === 'absent') return 'no root policy at ' + POLICY_PATH + ', so only the built-in rules apply'
  if (load.state === 'invalid') {
    return 'the root policy ' + POLICY_PATH + ' is invalid (' + load.reason + '), so every guarded step is denied until root fixes it'
  }
  const a = load.policy.added
  return (
    'the root policy ' + POLICY_PATH + ' adds ' +
    a.redaction.length + ' redaction rule(s), ' +
    a.injection_phrases.length + ' injection phrase(s), ' +
    a.secret_paths.length + ' secret path(s) and ' +
    a.outward_commands.length + ' outward command(s) to the built-in rules'
  )
}
