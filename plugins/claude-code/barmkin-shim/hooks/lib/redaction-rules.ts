import { bearerSpans, genericKeyEnvSpans, jwtSpans, pemSpans, type SpanScanner } from './linear-scanners'

// Secret-detection patterns. Shaped like barmkin's rules.yaml "Secrets"
// section (name/pattern/example) plus jev.go's pre-egress secretPatterns,
// unioned into one list. Kept here as TS literals rather than a parsed
// rules.yaml: mods have no file-system-relative config loading step and no
// YAML dependency, and a plugin is installed as its own folder, apart from
// the rest of this repository. Ported from barmkin-mod. When rules.yaml's
// secrets section changes, update this list by hand and re-check the
// `example` vectors in redaction.test.ts.
export interface RedactionRule {
  name: string
  // Must carry the "g" flag so redactText can replace every match.
  pattern: RegExp
  // An exact linear-time stand-in for `pattern`, for the four rules whose
  // regexes are expensive on crafted input (see linear-scanners.ts). When
  // present, every scan uses it instead of the regex; the regex stays as the
  // rule's specification and as the reference tests/linear-scanners.test.ts
  // compares it with.
  scan?: SpanScanner
  category: string
  example: string
}

export const REDACTION_RULES: RedactionRule[] = [
  {
    name: 'private-key-block',
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    scan: pemSpans,
    category: 'private-key',
    example: '-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----',
  },
  {
    name: 'jwt',
    pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    scan: jwtSpans,
    category: 'jwt',
    example: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  },
  // Ordered ahead of generic-key-env-assignment so AWS_ACCESS_KEY_ID=AKIA...
  // keeps its aws-key label; that rule skips the resulting placeholder.
  {
    name: 'aws-access-key',
    pattern: /\b(AKIA|ASIA)[A-Z0-9]{16}\b/g,
    category: 'aws-key',
    example: 'AKIAIOSFODNN7EXAMPLE',
  },
  // Ordered ahead of the vendor-prefix rules below on purpose: a vendor key
  // assigned to a *_KEY=/*_SECRET=/etc. name (e.g. STRIPE_SECRET_KEY="sk_live_...")
  // should redact once, as this rule's whole quoted/bare value, rather than
  // the vendor rule consuming the key first and this rule then matching
  // its own `[REDACTED:...]` placeholder (which also has a name= shape and
  // a digit in it). A vendor key with no assignment around it (bare in
  // JSON, in a URL, pasted alone) has no `=` for this rule to match, so the
  // vendor-specific rules below still catch it exactly as before.
  //
  // Only a bare literal counts, wherever it sits on the line: a quoted string
  // not followed by an operator or accessor, or a whole unquoted token with
  // no code syntax (calls, indexing, attribute access, template literals, a
  // leading $VAR reference or ${...} interpolation, quoted or not). Code
  // expressions assigned to a *_KEY constant are left alone, so a secret built
  // by code or containing those characters unquoted is a known gap. The name
  // class covers _KEY/SECRET/TOKEN/PASSWORD/PASSWD/CREDENTIAL(S)/_PAT anywhere
  // in the name, so DB_PASSWORD_PROD=, API_TOKEN2= and similar assignments
  // redact the same way *_KEY= already did. A reference is not a secret: a name
  // ending in _FILE, _PATH, _DIR or _URL is left alone, so
  // DB_PASSWORD_FILE=/run/secrets/... stays unredacted. The value is not
  // inspected for a leading slash, since a base64 secret can start with one.
  // The value needs a digit, for every name. A letters-only secret assigned to
  // TOKEN/PASSWORD/PASSWD/CREDENTIAL(S)/_PAT is a known gap: a 19+ letter run
  // with no separator is indistinguishable from a code identifier
  // (const token = refreshedAccessTokenValue;), so it is not redacted.
  {
    name: 'generic-key-env-assignment',
    pattern:
      /\b(?=(?<name>[A-Z0-9_]*(?:(?<=_)KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIALS?|_PAT(?![A-Z]))[A-Z0-9_]*))\k<name>(?<!_FILE|_PATH|_DIR|_URL)[ \t]*=[ \t]*(?:(?<q>['"])(?!\$|\[REDACTED:)(?![^'"\s]*\$\{)(?=[^'"\s]*\d)[^'"\s]{16,}\k<q>(?![ \t]*[-+*\/%.[(])|(?!\$)(?=[^\s'"`()[\]{}.;,]*\d)[^\s'"`()[\]{}.;,]{16,}(?![^\s;,'"`]))/gi,
    scan: genericKeyEnvSpans,
    category: 'env-key',
    example: 'AWS_SECRET_KEY=abcdef0123456789',
  },
  // Anthropic key prefixes (api/admin/oat/ort), replacing the old bare
  // `sk-[A-Za-z0-9]{10,}` rule that only matched a key with no hyphens or
  // underscores in its body -- which no current Anthropic key shape is.
  {
    name: 'anthropic-key',
    pattern: /\bsk-ant-(?:api|admin|oat|ort)\d{2}-[A-Za-z0-9_-]{20,}\b/g,
    category: 'api-key',
    example: 'sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  },
  // The Microsoft Claude Code Action incident: an attacker stripped the
  // `sk-ant-` vendor prefix to evade a prefix-only scan, leaving the
  // `api0<N>-<body>` remainder intact. Catches the body shape on its own.
  {
    name: 'anthropic-key-stripped-prefix',
    pattern: /\bapi0\d-[A-Za-z0-9_-]{60,}\b/g,
    category: 'api-key',
    example: 'api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-ABCDEFGH',
  },
  {
    name: 'openai-project-key',
    pattern: /\bsk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}\b/g,
    category: 'api-key',
    example: 'sk-proj-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  },
  {
    name: 'openrouter-key',
    pattern: /\bsk-or-v1-[a-f0-9]{32,}\b/g,
    category: 'api-key',
    example: 'sk-or-v1-' + 'a1b2c3d4e5f6'.repeat(3),
  },
  // Legacy OpenAI (and rk-) key shape: no hyphens in the body, so this can't
  // swallow the hyphenated vendor prefixes above (their first segments are
  // shorter than 10 characters, so the alphanumeric run ends before the floor).
  {
    name: 'openai-legacy-key',
    pattern: /\b(?:sk|rk)-[A-Za-z0-9]{10,}\b/g,
    category: 'api-key',
    example: 'sk-ABCDEFGHIJ1234567890',
  },
  {
    name: 'github-token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
    category: 'github-token',
    example: 'ghp_AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIII',
  },
  {
    name: 'github-fine-grained-pat',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    category: 'github-token',
    example: 'github_pat_' + '11AAAAAAA0'.repeat(3),
  },
  {
    name: 'stripe-key',
    pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g,
    category: 'stripe-key',
    example: 'sk_live_4eC39HqLyjWDarjtT1zdp7dc',
  },
  {
    name: 'google-api-key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    category: 'google-api-key',
    example: 'AIza' + 'Sy'.padEnd(35, 'A1b2C3'),
  },
  {
    name: 'npm-token',
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    category: 'npm-token',
    example: 'npm_' + 'A1b2C3d4E5f6'.repeat(3),
  },
  {
    name: 'huggingface-token',
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
    category: 'huggingface-token',
    example: 'hf_' + 'A1b2C3d4E5f6'.repeat(3),
  },
  // Broadened from the original [bpras] to also catch the newer app
  // (xoxo-prefix-free rename aside), config/exchange (xoxe) and o-class
  // tokens Slack has since added.
  {
    name: 'slack-token',
    pattern: /\bxox[abeoprs]-[A-Za-z0-9-]+/g,
    category: 'slack-token',
    example: 'xoxb-1234567890-abcdefghij',
  },
  {
    name: 'slack-webhook',
    pattern: /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g,
    category: 'slack-webhook',
    example: 'https://hooks.slack.com/' + 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX',
  },
  // A URL's userinfo segment, scheme through the `@`: redacts the whole
  // `scheme://user:password@` prefix rather than only the password, since
  // redactText replaces a rule's whole match and this module keeps that
  // one substitution model everywhere (no capture-group-aware rewrite).
  // The host and path after `@` are left visible.
  {
    name: 'url-userinfo-password',
    pattern: /\b[a-z][a-z0-9+.-]{0,31}:\/\/[^\s/:@]+:[^\s/@]{6,}@/g,
    category: 'url-credential',
    example: 'postgres://dbuser:S3cureP4ssw0rd@db.example.com:5432/mydb',
  },
  // Variable-length, matching gitlab's own current token lengths rather
  // than pinning to the 20-char length some older tokens used.
  {
    name: 'gitlab-token',
    pattern: /\bglpat-[A-Za-z0-9_-]{20,}\b/g,
    category: 'gitlab-token',
    example: 'glpat-AAAAAAAAAAAAAAAAAAAA',
  },
  {
    name: 'generic-apikey-assignment',
    pattern: /\bapikey_[A-Za-z0-9]+\b/gi,
    category: 'api-key',
    example: 'apikey_1234567890abcdef',
  },
  {
    name: 'bearer-header',
    pattern: /\bBearer\s+(?=[A-Za-z0-9._~+\/-]*\d)[A-Za-z0-9._~+\/-]{20,}=*/gi,
    scan: bearerSpans,
    category: 'bearer-token',
    example: 'Bearer eyJhbGciOiJIUzI1NiJ9.abc.def',
  },
]
