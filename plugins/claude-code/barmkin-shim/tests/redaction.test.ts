import { expect, test } from 'claude-code/testing'
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactText, redactInEitherView, classifierInput, containsAnySecret, containsSecretInEitherView, exceedsResultBudget, exceedsScanLimit, measureResult } from '../hooks/lib/redaction'
import { scrubInvisible } from '../hooks/lib/scrub'

test('redacts every example vector with a numbered placeholder', () => {
  // Each rule is checked against its own example in isolation. Running the
  // full rule set here would be order-dependent: e.g. bearer-header's
  // example also matches jwt (which runs first), so jwt's placeholder
  // would consume the match before bearer-header's own pattern ever saw
  // it. That's correct redaction behavior (the secret still gets caught),
  // just not what this test is checking rule-by-rule.
  for (const rule of REDACTION_RULES) {
    const { text, redactedCount, categories } = redactText(rule.example, [rule], {})
    expect(redactedCount > 0).toBe(true)
    expect(text).toMatch(new RegExp('\\[REDACTED:' + rule.category + '#\\d+\\]'))
    expect(categories).toContain(rule.category)
  }
})

test('every example vector is caught somewhere by the full rule set', () => {
  // The ordering-sensitivity above is fine as long as the full set never
  // lets an example vector through unredacted.
  for (const rule of REDACTION_RULES) {
    const { redactedCount } = redactText(rule.example, REDACTION_RULES, {})
    expect(redactedCount > 0).toBe(true)
  }
})

test('numbers placeholders per category across repeated calls', () => {
  const counters: Record<string, number> = {}
  const first = redactText('key one: AKIAIOSFODNN7EXAMPLE', REDACTION_RULES, counters)
  const second = redactText('key two: AKIAIOSFODNN7EXAMPLF', REDACTION_RULES, counters)
  expect(first.text).toContain('[REDACTED:aws-key#1]')
  expect(second.text).toContain('[REDACTED:aws-key#2]')
})

test('keeps the aws-key label for an AKIA key assigned to AWS_ACCESS_KEY_ID', () => {
  for (const line of ['export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"']) {
    const { text, redactedCount } = redactText(line, REDACTION_RULES, {})
    expect(redactedCount).toBe(1)
    expect(text).toBe(line.replace('AKIAIOSFODNN7EXAMPLE', '[REDACTED:aws-key#1]'))
  }
})

test('leaves ordinary text untouched', () => {
  const { text, redactedCount } = redactText('ls -la /tmp', REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe('ls -la /tmp')
})

test('containsAnySecret is safe to call repeatedly (no stale regex lastIndex)', () => {
  const withSecret = 'token: ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII'
  expect(containsAnySecret(withSecret, REDACTION_RULES)).toBe(true)
  expect(containsAnySecret(withSecret, REDACTION_RULES)).toBe(true)
  expect(containsAnySecret('nothing to see here', REDACTION_RULES)).toBe(false)
})

test('leaves ordinary source and prose that mention keys or Bearer unchanged', () => {
  const source = [
    "CACHE_KEY = 'user'",
    'PRIMARY_KEY = "id"',
    'SORT_KEY=name',
    'Clients use Bearer authentication for every request.',
    "headers['Authorization'] = 'Bearer ' + token",
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('still redacts real secret values assigned to *_KEY or sent as Bearer tokens', () => {
  const input = [
    'AWS_SECRET_ACCESS_KEY = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"',
    'Authorization: Bearer 9f8e7d6c5b4a39281706f5e4d3c2b1a0',
  ].join('\n')
  const { text, redactedCount } = redactText(input, REDACTION_RULES, {})
  expect(redactedCount).toBe(3)
  expect(text).not.toContain('wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
  expect(text).not.toContain('sk_live_4eC39HqLyjWDarjtT1zdp7dc')
  expect(text).not.toContain('9f8e7d6c5b4a39281706f5e4d3c2b1a0')
})

test('redacts the whole *_KEY value even when it contains punctuation', () => {
  const cases = [
    "SECRET_KEY = 'django-insecure-k3$9!x@7v#q2(w)0z+e8&r^t5u%y1i*o4p'",
    'DB_KEY=Xk9#mP2$vL8@qR4!wN7z',
    'API_KEY=f3b9c0d8a7e6152493ab',
    'CLIENT_SECRET="Zq8$w!Rk2@pL9#xV5^mN"',
  ]
  for (const line of cases) {
    const { text, redactedCount } = redactText(line, REDACTION_RULES, {})
    expect(redactedCount).toBe(1)
    expect(text).toBe('[REDACTED:env-key#1]')
  }
})

test('never redacts code expressions assigned to a *_KEY constant', () => {
  const source = [
    'CACHE_KEY = hashlib.sha256(data).hexdigest()',
    'SIGNING_KEY=settings.SECRET_KEY_V2_2024',
    'ENCRYPTION_KEY = base64.b64decode(os.environ["ENC"])',
    'const STORAGE_KEY = `app:v2:${userId}`;',
    "SESSION_KEY = 'prefix_2024_' + user_id",
    'DEPLOY_KEY=$DEPLOY_KEY_FROM_CI_2024',
    'SSH_KEY="$HOME/.ssh/id_ed25519"',
    'export AWS_SECRET_KEY="${S3_SECRET_KEY}"',
    'SSH_KEY="${HOME}/.ssh/id_rsa_2024"',
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('redacts a short sk- or rk- key with a 10-character body', () => {
  const source = 'sk-ABCDEFGHIJ123 and rk-ABCDEFGHIJ123'
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(2)
  expect(text).not.toContain('ABCDEFGHIJ123')
})

test('redacts a secret whose name has no underscore before the keyword or ends in a digit', () => {
  const value = 'xK9mP2qL7vN4wR8tY3uI'
  const source = [`JWTSECRET=${value}`, `API_KEY2=${value}`, `SECRET2=${value}`].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(3)
  expect(text).not.toContain(value)
})

test('never redacts a path-valued variable whose name only contains a keyword as a substring', () => {
  const source = [
    'export LD_LIBRARY_PATH=/usr/lib/x86_64-linux-gnu',
    'PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig',
    'CONFIG_PATH=/usr/local/share/myapp2024',
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('never redacts code expressions assigned to a *_TOKEN/*_PASSWORD/*_CREDENTIALS constant', () => {
  const source = [
    'CSRF_TOKEN = generate_csrf_token()',
    'RESET_PASSWORD_URL = "/reset"',
    'const ACCESS_TOKEN = `Bearer ${jwt}`;',
    'AWS_CREDENTIALS=session.get_credentials()',
    'API_PASSWD="${DB_PASSWD}"',
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

test('redacts a secret literal on one line without touching its neighbours', () => {
  const input = "DEBUG = True\nSECRET_KEY = 'django-insecure-k3$9!x@7v#q2(w)0z+e8&r^t5u%y1i*o4p'\nCACHE_KEY = 'user'"
  const { text } = redactText(input, REDACTION_RULES, {})
  expect(text).toBe("DEBUG = True\n[REDACTED:env-key#1]\nCACHE_KEY = 'user'")
})

test('redacts a bare literal secret that has other text after it on the same line', () => {
  const cases: Array<[string, string]> = [
    ['SECRET_VALUE=abc123def456ghi789jk npm start', '[REDACTED:env-key#1] npm start'],
    ['API_KEY=f3b9c0d8a7e6152493ab npm start', '[REDACTED:env-key#1] npm start'],
    ['docker run -e API_KEY=f3b9c0d8a7e6152493ab image', 'docker run -e [REDACTED:env-key#1] image'],
    ['DB_KEY=Xk9#mP2$vL8@qR4!wN7z npm test && echo done', '[REDACTED:env-key#1] npm test && echo done'],
    ['docker run -e "API_KEY=f3b9c0d8a7e6152493ab" img', 'docker run -e "[REDACTED:env-key#1]" img'],
    ["export 'DB_KEY=Xk9#mP2$vL8@qR4!wN7z'", "export '[REDACTED:env-key#1]'"],
    ['["API_KEY=f3b9c0d8a7e6152493ab"]', '["[REDACTED:env-key#1]"]'],
    ['Set `API_KEY=f3b9c0d8a7e6152493ab` first', 'Set `[REDACTED:env-key#1]` first'],
    ["SECRET_KEY = 'django-insecure-k3$9!x@7v#q2(w)0z+e8&r^t5u%y1i*o4p'  # dev only", '[REDACTED:env-key#1]  # dev only'],
  ]
  for (const [input, expected] of cases) {
    expect(redactText(input, REDACTION_RULES, {}).text).toBe(expected)
  }
})

test('never redacts part of an unquoted token or a quoted literal used in an expression', () => {
  const source = [
    'API_KEY=abcdef0123456789abcd.secretTAIL99',
    "SESSION_KEY = 'abcdef0123456789abcd' + user_id",
    "TOKEN_KEY = 'abcdef0123456789abcd'.encode()",
    'CACHE_KEY = hashlib_sha256_digest_v2(data)',
    'foo(API_KEY=some_identifier_2024)',
  ].join('\n')
  const { text, redactedCount } = redactText(source, REDACTION_RULES, {})
  expect(redactedCount).toBe(0)
  expect(text).toBe(source)
})

// 20-sample corpus of vendor-prefix, assignment-name and known-gap vectors,
// one per category the rule set covers. 15 of 20 are missed by main's rules
// and redacted by this rule set; 2 are baselines that already redacted on
// main, and the remaining 3 are documented, deliberate gaps (see the final
// block) -- not silently dropped, since inventing an unprincipled regex for a
// bare high-entropy string risks corrupting ordinary text (hashes, ids) with
// no real detection benefit. The baseline vectors below are here only so a
// future rule-set change can't silently regress them.
test('corpus: vendor-prefix vectors the rule set newly catches', () => {
  const vectors: Array<[string, string]> = [
    ['anthropic sk-ant-api03 bare', 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    [
      'anthropic key in JSON',
      '{"ANTHROPIC_API_KEY": "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ"}',
    ],
    [
      'anthropic minus prefix (MS case)',
      'api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-ABCDEFGH',
    ],
    ['openai sk-proj', 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
    ['openrouter sk-or-v1', 'sk-or-v1-' + 'a1b2c3d4e5f6'.repeat(3)],
    ['stripe sk_live_', 'STRIPE_SECRET_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"'],
    ['github fine-grained PAT', 'github_pat_' + '11AAAAAAA0'.repeat(3)],
    ['google api key (AIza...)', 'AIza' + 'Sy'.padEnd(35, 'A1b2C3')],
    ['npm token', 'npm_' + 'A1b2C3d4E5f6'.repeat(3)],
    ['hf token', 'hf_' + 'A1b2C3d4E5f6'.repeat(3)],
    ['DB_PASSWORD env', 'DB_PASSWORD=Sup3rSecretPassw0rd'],
    ['lowercase db_password config', 'db_password=Sup3rSecretPassw0rd'],
    ['API_TOKEN env', 'API_TOKEN=abcdef0123456789abcd'],
    ['postgres url w/ password', 'postgres://dbuser:S3cureP4ssw0rd@db.example.com:5432/mydb'],
    ['slack webhook', 'https://hooks.slack.com/' + 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'],
  ]
  for (const [, sample] of vectors) {
    const { redactedCount } = redactText(sample, REDACTION_RULES, {})
    expect(redactedCount > 0).toBe(true)
  }
})

test('corpus: baseline vectors that already redacted on main keep redacting', () => {
  const vectors: Array<[string, string]> = [
    ['openai legacy sk-', 'sk-ABCDEFGHIJ1234567890'],
    ['ANTHROPIC_API_KEY env (via *_KEY=)', 'ANTHROPIC_API_KEY=abcdef0123456789abcd'],
  ]
  for (const [, sample] of vectors) {
    const { redactedCount } = redactText(sample, REDACTION_RULES, {})
    expect(redactedCount > 0).toBe(true)
  }
})

// Deliberately not covered: each needs either decoding (base64) or a
// bare-high-entropy-string heuristic with no safe signal to anchor on (no
// vendor prefix, no *_KEY=-style name, no reliable shape), which would risk
// flagging ordinary hashes, ids and tokens as secrets. Tracked as open gaps,
// not silently dropped.
test('corpus: known gaps this rule set does not close', () => {
  const bareAwsSecret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  expect(containsAnySecret(bareAwsSecret, REDACTION_RULES)).toBe(false)

  // Google's own docs call `private_key_id` a non-sensitive rotation id --
  // only the accompanying `private_key` PEM (already caught by the
  // private-key-block rule above) is the actual secret.
  const gcpPrivateKeyId = '"private_key_id": "3f29a6c1e4b8d0f27a51c6e9b4d7f3a8c2e5b1d0"'
  expect(containsAnySecret(gcpPrivateKeyId, REDACTION_RULES)).toBe(false)

  // s1ngularity-style evasion: base64 of an AWS key pair, decoded only by a
  // human or a tool that unwraps base64 before scanning.
  const base64OfAwsKey = btoa('AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
  expect(containsAnySecret(base64OfAwsKey, REDACTION_RULES)).toBe(false)
})

test('withholds text longer than the scan limit as a whole', () => {
  const secret = 'API_KEY=abcdef0123456789'
  const { text, redactedCount, categories } = redactText(secret + ' ' + 'x'.repeat(256 * 1024), REDACTION_RULES, {})
  expect(text).not.toContain('abcdef0123456789')
  expect(redactedCount).toBe(1)
  expect(categories).toEqual(['oversized'])
  expect(containsAnySecret(secret + ' ' + 'x'.repeat(256 * 1024), REDACTION_RULES)).toBe(false)
})

test('leaves a path named after a credential keyword alone', () => {
  for (const line of ['DB_PASSWORD_FILE=/run/secrets/db_password_v2', 'TOKENIZER_PATH=/opt/models/tokenizer_v2_large']) {
    expect(redactText(line, REDACTION_RULES, {}).redactedCount).toBe(0)
  }
})

test('redacts an assignment whose credential keyword sits mid-name', () => {
  for (const line of [
    'DB_PASSWORD_PROD=Sup3rS3cretValue99',
    'GITHUB_TOKEN_V2=xK9mP2qL7vN4wR8tY3uI',
    'API_TOKEN2=xK9mP2qL7vN4wR8tY3uI',
    'AWS_SECRET_ACCESS_KEY=/K7MDENG/bPxRfiCYEXAMPLEKEY1',
    'DB_PASSWORD=/aB3dE5fG7hJ9kL1mN3pQ',
  ]) {
    expect(redactText(line, REDACTION_RULES, {}).categories).toContain('env-key')
  }
})

test('redacts a lowercase credential assignment the same as an uppercase one', () => {
  for (const line of [
    'db_password=Sup3rS3cretValue99',
    'password = "Sup3rS3cretValue99"',
    'api_token2=xK9mP2qL7vN4wR8tY3uI',
    'github_pat_prod = "xK9mP2qL7vN4wR8tY3uI"',
  ]) {
    expect(redactText(line, REDACTION_RULES, {}).categories).toContain('env-key')
  }
  expect(redactText('db_password_file=/run/secrets/db_password_v2', REDACTION_RULES, {}).redactedCount).toBe(0)
})

test('helper-level: detection on a zero-width-split AKIA key holds only after the scrub runs', () => {
  const split = 'my key is AKIA​IOSFODNN7EXAMPLE, use it'
  expect(containsAnySecret(split, REDACTION_RULES)).toBe(false)
  expect(containsAnySecret(scrubInvisible(split).text, REDACTION_RULES)).toBe(true)
  expect(redactText(scrubInvisible(split).text, REDACTION_RULES, {}).text).toContain('[REDACTED:aws-key#')
})

test('helper-level: a zero-width character before a key is seen on the original view, not the scrubbed one', () => {
  const hidden = 'key1​AKIAIOSFODNN7EXAMPLE'
  expect(containsAnySecret(hidden, REDACTION_RULES)).toBe(true)
  expect(containsAnySecret(scrubInvisible(hidden).text, REDACTION_RULES)).toBe(false)
})

test('helper-level: a two-pass redaction whose placeholders push the text past the scan limit is withheld, not collapsed', () => {
  const unit = 'SECRET=abcdefgh12345678;'
  const input = unit.repeat(10900)
  expect(exceedsScanLimit(input)).toBe(false)
  const out = redactInEitherView(input, REDACTION_RULES, { 'env-key': 100000 })
  expect(out.text).not.toContain('[REDACTED:oversized')
  expect(out.text).toContain('withheld')
  expect(out.redactedCount).toBeGreaterThan(0)
  expect(classifierInput(input, REDACTION_RULES, { 'env-key': 100000 })).toBeNull()
})

test('helper-level: the classifier receives the redacted text for ordinary input, and nothing for a withheld marker', () => {
  expect(classifierInput('plain page text', REDACTION_RULES, {})).toBe('plain page text')
  expect(classifierInput('SECRET=abcdefgh12345678;'.repeat(10900), REDACTION_RULES, { 'env-key': 100000 })).toBeNull()
})

test('helper-level: a secret hidden behind a zero-width character is refused on both views', () => {
  const hidden = 'key1​AKIAIOSFODNN7EXAMPLE'
  const scrubbedOnly = 'AKIA​IOSFODNN7EXAMPLE'
  expect(containsSecretInEitherView(hidden, REDACTION_RULES)).toBe(true)
  expect(containsSecretInEitherView(scrubbedOnly, REDACTION_RULES)).toBe(true)
  expect(containsSecretInEitherView('plain text with no key', REDACTION_RULES)).toBe(false)
})

test('helper-level: an outbound text with joiners and no secret is left unredacted, so the original is forwarded', () => {
  const typed = 'family 👨‍👩‍👧 and क्‍ष and ‌fine'
  expect(redactText(scrubInvisible(typed).text, REDACTION_RULES, {}).redactedCount).toBe(0)
  expect(containsAnySecret(scrubInvisible(typed).text, REDACTION_RULES)).toBe(false)
})

test('leaves a letters-only password-class value unredacted (documented gap)', () => {
  for (const line of [
    'DB_PASSWORD=correcthorsebatterystaple',
    'DB_PASSWORD="correcthorsebatterystaple"',
    'db_password=supersecretpassword',
  ]) {
    expect(redactText(line, REDACTION_RULES, {}).redactedCount).toBe(0)
  }
})

test('leaves a reference to a path or URL under a credential-keyword name alone', () => {
  const references = [
    'DB_PASSWORD_FILE=/run/secrets/db_password_v2',
    'TOKENIZER_PATH=/opt/models/tokenizer_v2_large',
    'DB_TOKEN_DIR=cache_v2_large_entries',
    'AUTH_TOKEN_URL=abcdef0123456789abcd',
  ]
  for (const line of references) {
    expect(redactText(line, REDACTION_RULES, {}).redactedCount).toBe(0)
  }
})

test('redacts a JWT that follows a separator or a hyphen', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'
  for (const line of ['token=' + jwt, 'x-auth-' + jwt]) {
    expect(redactText(line, REDACTION_RULES, {}).categories).toContain('jwt')
  }
})

test('counts a result and its model-visible text mirror once against the aggregate budget', () => {
  const chunk = 'x'.repeat(200 * 1024)
  expect(exceedsResultBudget({ result: [chunk, chunk, chunk, chunk], text: chunk })).toBe(false)
  expect(measureResult({ result: [chunk, chunk, chunk, chunk], text: chunk })).toBe('within')
})

test('classifies a tool result against the per-string cap and the aggregate budget', () => {
  const chunk = 'x'.repeat(200 * 1024)
  // One string over the per-string cap, the strings together within the total.
  expect(measureResult({ text: 'x'.repeat(300 * 1024) })).toBe('long-string')
  expect(exceedsResultBudget({ text: 'x'.repeat(300 * 1024) })).toBe(true)
  expect(measureResult({ result: 'x'.repeat(600 * 1024) })).toBe('long-string')
  // Every string within the cap, together over the total.
  expect(measureResult([chunk, { stdout: chunk }, chunk, chunk])).toBe('within')
  expect(measureResult(Array.from({ length: 6 }, () => chunk))).toBe('over-total')
  expect(exceedsResultBudget(Array.from({ length: 6 }, () => chunk))).toBe(true)
  // Over the total takes precedence, since a prefix does not shrink the rest.
  expect(measureResult({ result: 'x'.repeat(2 * 1024 * 1024) })).toBe('over-total')
})

test('still scans text right at the scan limit', () => {
  const head = 'API_KEY=abcdef0123456789 '
  const atLimit = head + 'x'.repeat(256 * 1024 - head.length)
  const { text, redactedCount, categories } = redactText(atLimit, REDACTION_RULES, {})
  expect(text).not.toContain('abcdef0123456789')
  expect(redactedCount).toBe(1)
  expect(categories).toEqual(['env-key'])
})
