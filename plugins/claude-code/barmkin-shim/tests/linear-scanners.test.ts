import { expect, test } from 'claude-code/testing'
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactText, containsAnySecret } from '../hooks/lib/redaction'
import { bearerSpans, genericKeyEnvSpans, jwtSpans, pemScan, pemSpans, type Span, type SpanScanner } from '../hooks/lib/linear-scanners'
import { ALNUM, pemHeader, randOf, worstInputs, type Rand } from './fuzz-support'

// The regexes the four scanners replace, kept here verbatim as the reference
// they must match span for span. The first test ties them to the live rules,
// so a rule edit that is not mirrored in its scanner fails there.
const REFERENCE: Record<string, { pattern: RegExp; scan: SpanScanner }> = {
  'private-key-block': { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, scan: pemSpans },
  jwt: { pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, scan: jwtSpans },
  'generic-key-env-assignment': {
    pattern:
      /\b(?=(?<name>[A-Z0-9_]*(?:(?<=_)KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|_PAT(?![A-Z]))[A-Z0-9_]*))\k<name>(?<!_FILE|_PATH|_DIR|_URL)[ \t]*=[ \t]*(?:(?<q>['"])(?!\$|\[REDACTED:)(?![^'"\s]*\$\{)(?=[^'"\s]*\d)[^'"\s]{16,}\k<q>(?![ \t]*[-+*\/%.[(])|(?!\$)(?=[^\s'"`()[\]{}.;,]*\d)[^\s'"`()[\]{}.;,]{16,}(?![^\s;,'"`]))/gi,
    scan: genericKeyEnvSpans,
  },
  'bearer-header': { pattern: /\bBearer\s+(?=[A-Za-z0-9._~+\/-]*\d)[A-Za-z0-9._~+\/-]{20,}=*/gi, scan: bearerSpans },
}

function referenceSpans(pattern: RegExp, text: string): Span[] {
  return [...text.matchAll(new RegExp(pattern.source, pattern.flags))].map((m) => ({ start: m.index ?? 0, end: (m.index ?? 0) + m[0].length }))
}

// Fragments whose concatenations land on every edge of the four rules: names
// with and without a keyword and with reference suffixes, blanks around `=`,
// quotes, operators after a quote, `${`, `$`, `[REDACTED:`, digits, JWT and
// PEM pieces, Bearer with assorted whitespace, hyphens and dots.
const FRAGMENTS = [
  'SECRET', 'TOKEN', 'PASSWORD', 'PASSWD', 'CREDENTIALS', 'CREDENTIAL', '_KEY', 'KEY', '_PAT', 'PATH', 'api_', 'DB_', 'X', '_FILE', '_URL', '_DIR', '_PATH', 'secret', 'Token',
  '=', ' = ', ' =', '= ', '\t', ' ', '\n', '\r\n', '\u00a0', '\u2003', '\ufeff',
  '"', "'", '`', '(', ')', '[', ']', '{', '}', '.', ';', ',', '+', '-', '*', '/', '%', '_', '~', '$', '${', '$X', '[REDACTED:', '[redacted:x]',
  '0', '7', '123456', 'abcdefghij', 'abcdefghijklmnop', 'aB3dE5fG7hJ9kL1m', 'AAAAAAAAAAAAAAAAAAAA', 'xK9mP2qL7vN4wR8tY3uI',
  'eyJ', 'eyJhbGciOiJIUzI1NiJ9', '.', '.eyJzdWIiOiIxMjM0NTY3ODkwIn0.', 'dozjgNryP4J3', '-eyJ', 'eyJ-', 'eyJ.a.b', 'eyJa.b.-', 'eyJa.b.c-',
  'Bearer', 'bearer', 'BEARER ', 'Bearer ', 'Bearer\n', 'Bearer  \t', 'xBearer ', 'Bearer123456789012345678901234', '==', '=',
  // Characters the regex's case folding and word boundaries must not mistake for ASCII.
  '\u212a', '\u017f', '\u0131', '\u{1f600}', '\ud83d', 'TO\u212aEN', 'PA\u017fSWORD', 'ey\u0237', '\u00e9',
  '-----BEGIN ', '-----END ', 'RSA ', 'EC ', 'OPENSSH ', 'PRIVATE KEY', 'PRIVATE KEY-----', 'PRIVATE', ' KEY-----', '-----', 'MIIEvQIBADANBg', 'private key-----',
]

function fragmentString(rand: Rand, maxFragments: number): string {
  const n = rand.int(1, maxFragments)
  let out = ''
  for (let i = 0; i < n; i++) out += rand.pick(FRAGMENTS)
  return out
}

function assignmentString(rand: Rand): string {
  const names = ['DB_PASSWORD', 'api_token2', 'AWS_SECRET_KEY', 'GITHUB_PAT', 'github_pat_prod', 'MY_KEY', 'KEYS', 'TOKENIZER_PATH', 'SECRET_FILE', 'X_CREDENTIALS', 'plain', 'password']
  const values = [
    'abcdef0123456789',
    'Sup3rS3cretValue99',
    'letters only value here',
    rand.chars(ALNUM + '#$@!%^&*', rand.int(4, 40)),
    '${HOME}/x1',
    '$OTHER_VAR1234567890',
    '[REDACTED:env-key#1]',
    'a1b2c3d4e5f6g7h8i9',
  ]
  const quote = rand.pick(['', '', '"', "'", '`'])
  const gap = () => rand.pick(['', ' ', '\t', '  ', '\n', ' \u00a0'])
  const tail = rand.pick(['', ' ', ';', ',', ' + x', '.length', '[0]', '(', ' - 1', '\n', "'", ')', '}'])
  return rand.pick(names) + gap() + '=' + gap() + quote + rand.pick(values) + (quote === '' ? '' : rand.next() < 0.1 ? '' : quote) + tail
}

function jwtString(rand: Rand): string {
  const seg = () => rand.chars(ALNUM + '_-', rand.int(0, 12))
  const dot = () => (rand.next() < 0.08 ? '' : '.')
  return rand.pick(['', 'x', '-', ' ', '=', 'a.']) + 'eyJ' + seg() + dot() + seg() + dot() + seg() + rand.pick(['', '-', '--', '.', ' x', '_'])
}

function pemString(rand: Rand): string {
  const header = (kind: string) => '-----' + kind + ' ' + rand.pick(['', 'RSA ', 'EC ', 'OPENSSH ', 'rsa ', 'X1 ']) + rand.pick(['PRIVATE KEY', 'PRIVATE KEY', 'PUBLIC KEY']) + rand.pick(['-----', '-----', '----'])
  const blocks = rand.int(1, 3)
  let out = ''
  for (let i = 0; i < blocks; i++) {
    out += header('BEGIN') + '\n' + rand.chars(ALNUM, rand.int(0, 20)) + '\n'
    if (rand.next() < 0.7) out += header('END') + rand.pick(['', '\n', ' tail'])
    out += rand.pick(['', ' ', '\n'])
  }
  return out
}

function bearerString(rand: Rand): string {
  const token = rand.chars(ALNUM + '._~+/-', rand.int(5, 40))
  return rand.pick(['', 'Authorization: ', 'x', '"']) + rand.pick(['Bearer', 'bearer', 'BEARER']) + rand.pick([' ', '  ', '\n', '\t', '', '\u00a0']) + token + rand.pick(['', '=', '==', ' ', '"'])
}

function structuredString(rand: Rand): string {
  const parts = rand.int(1, 4)
  let out = ''
  for (let i = 0; i < parts; i++) {
    const kind = rand.int(0, 4)
    out += [assignmentString, jwtString, pemString, bearerString, (r: Rand) => fragmentString(r, 12)][kind](rand) + rand.pick(['', ' ', '\n', ' ; '])
  }
  return out
}

test('the reference regexes are the live rules', () => {
  for (const [name, { pattern, scan }] of Object.entries(REFERENCE)) {
    const rule = REDACTION_RULES.find((r) => r.name === name)
    expect(rule).toBeDefined()
    expect(rule?.pattern.source).toBe(pattern.source)
    expect(rule?.pattern.flags).toBe(pattern.flags)
    expect(rule?.scan).toBe(scan)
  }
  expect(REDACTION_RULES.filter((r) => r.scan).map((r) => r.name).sort()).toEqual(Object.keys(REFERENCE).sort())
})

function checkAgainstReference(text: string, label: string): number {
  let mismatches = 0
  for (const [name, { pattern, scan }] of Object.entries(REFERENCE)) {
    const want = JSON.stringify(referenceSpans(pattern, text))
    const got = JSON.stringify(scan(text))
    if (want !== got) {
      mismatches++
      if (mismatches === 1) throw new Error(label + ' ' + name + ' differs on ' + JSON.stringify(text) + '\nregex   ' + want + '\nscanner ' + got)
    }
  }
  return mismatches
}

test('the linear scanners find exactly the spans the regexes do on 12,000 seeded strings', () => {
  const rand = randOf(20261009)
  let withMatch = 0
  for (let trial = 0; trial < 12000; trial++) {
    const text = trial % 3 === 0 ? fragmentString(rand, 40) : structuredString(rand)
    checkAgainstReference(text, 'trial ' + trial)
    if (REDACTION_RULES.some((r) => r.scan && r.scan(text).length > 0)) withMatch++
  }
  // The corpus must exercise matches, not only misses.
  expect(withMatch).toBeGreaterThan(2000)
})

test('the linear scanners match the regexes on joined documents of 8-24 KiB', () => {
  const rand = randOf(77)
  for (let trial = 0; trial < 60; trial++) {
    let text = ''
    const target = rand.int(8, 24) * 1024
    while (text.length < target) text += structuredString(rand) + rand.pick(['\n', ' ', '', '\n\n'])
    checkAgainstReference(text, 'document ' + trial)
  }
})

test('the linear scanners match the regexes on small-alphabet stress strings', () => {
  const rand = randOf(5)
  const alphabets = ['eyJ.-a', 'SECRET= 1"\n', 'Bearer 9a-.\n', '-BEGIN ENDRSA PRIVATEKY\n', 'K_EY=1a $"{', 'TOKEN_= \t9.a']
  for (let trial = 0; trial < 6000; trial++) {
    const alphabet = alphabets[trial % alphabets.length]
    checkAgainstReference(rand.chars(alphabet, rand.int(1, 70)), 'stress ' + trial)
  }
})

test('the linear scanners keep the cases the existing rules were written for', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
  expect(jwtSpans('x-auth-' + jwt)).toEqual([{ start: 7, end: 7 + jwt.length }])
  expect(jwtSpans('x' + jwt)).toEqual([])
  expect(genericKeyEnvSpans('DB_PASSWORD_FILE=/run/secrets/db_password_v2')).toEqual([])
  expect(genericKeyEnvSpans("CACHE_KEY = 'user'")).toEqual([])
  expect(genericKeyEnvSpans('AWS_SECRET_KEY=abcdef0123456789')).toEqual([{ start: 0, end: 31 }])
  expect(bearerSpans('Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def==')).toEqual([{ start: 15, end: 52 }])
  const pem = pemHeader('BEGIN', 'RSA ') + '\nAAAA\n' + pemHeader('END', 'RSA ')
  expect(pemSpans('x ' + pem + ' y')).toEqual([{ start: 2, end: 2 + pem.length }])
})

test('pemScan reports the first private-key header nothing closes', () => {
  const closed = pemHeader('BEGIN', 'RSA ') + '\nAAAA\n' + pemHeader('END', 'RSA ')
  expect(pemScan(closed).unclosedFrom).toBe(-1)
  expect(pemScan('head ' + closed + '\n' + pemHeader('BEGIN') + '\nBBBB').unclosedFrom).toBe(5 + closed.length + 1)
  expect(pemScan('-----BEGIN CERTIFICATE-----\nAAAA').unclosedFrom).toBe(-1)
  expect(pemScan(pemHeader('END', 'RSA ') + '\n' + pemHeader('BEGIN') + '\nAAAA').unclosedFrom).toBe(30)
})

// The worst shapes cost the regexes seconds at 256 KiB and minutes at 1 MiB.
// The scanners make one pass, so 1 MiB of each finishes inside a fixed budget
// that is generous against their measured cost (tens of milliseconds) and
// short of the regexes' by orders of magnitude.
test('every linear scanner takes linear time on 1 MiB of its worst input', () => {
  const size = 1024 * 1024
  const slow: string[] = []
  for (const [label, text] of Object.entries(worstInputs(size))) {
    for (const [name, { scan }] of Object.entries(REFERENCE)) {
      const started = performance.now()
      scan(text)
      const elapsed = performance.now() - started
      if (elapsed >= 1500) slow.push(name + ' on ' + label + ' took ' + elapsed.toFixed(0) + ' ms')
    }
  }
  expect(slow).toEqual([])
})

test('redactText gives the same output at any size through the scanners as through the regexes', () => {
  const rand = randOf(31)
  for (let trial = 0; trial < 300; trial++) {
    const text = structuredString(rand) + structuredString(rand)
    const viaScanners = redactText(text, REDACTION_RULES, {})
    const viaRegexes = redactText(text, REDACTION_RULES.map((r) => ({ ...r, scan: undefined })), {})
    expect(viaScanners).toEqual(viaRegexes)
  }
})

test('containsAnySecret uses the scanners', () => {
  expect(containsAnySecret('x '.repeat(100) + 'AWS_SECRET_KEY=abcdef0123456789', REDACTION_RULES)).toBe(true)
  expect(containsAnySecret('SECRET='.repeat(30000), REDACTION_RULES)).toBe(false)
})
