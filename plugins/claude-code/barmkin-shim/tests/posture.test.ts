import { expect, test } from 'claude-code/testing'
import { checkPosture } from '../hooks/lib/posture'

const GOOD_SEAT = { merged: { sandbox: { enabled: true }, disableSkillShellExecution: true }, policy: { prependPlugins: ['barmkin-shim@acme', 'sec-default@builtin'] } }

test('warns when not seated in managed prependPlugins at all', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(true)
})

test('warns when sec-default is seated ahead of this plugin', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-shim@acme'] } },
    'barmkin-shim',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('the sec-default seat warning names skill.prompt, the skill-body screen it hides', () => {
  const warnings = checkPosture(
    { merged: {}, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-shim@acme'] } },
    'barmkin-shim',
    [],
  )
  expect(warnings.some((w) => w.includes('sec-default is seated ahead') && w.includes('skill.prompt'))).toBe(true)
})

test('does not warn about seating when this plugin is ahead of sec-default', () => {
  const warnings = checkPosture(
    { merged: { sandbox: { enabled: true }, disableSkillShellExecution: true }, policy: { prependPlugins: ['barmkin-shim@acme', 'sec-default@builtin'] } },
    'barmkin-shim',
    ['github'],
  )
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(false)
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(false)
})

test('warns on bypassPermissions default mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'bypassPermissions' } }, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(true)
})

test('does not warn on a non-bypass permission mode', () => {
  const warnings = checkPosture({ merged: { permissions: { defaultMode: 'default' } }, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('bypassPermissions'))).toBe(false)
})

test('warns when the sandbox is off or unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-shim', []).some((w) => w.includes('sandbox'))).toBe(true)
  expect(checkPosture({ merged: { sandbox: { enabled: false } }, policy: {} }, 'barmkin-shim', []).some((w) => w.includes('sandbox'))).toBe(true)
})

test('does not warn when the sandbox is explicitly enabled', () => {
  const warnings = checkPosture({ merged: { sandbox: { enabled: true } }, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('sandbox'))).toBe(false)
})

test('warns when disableSkillShellExecution is unset', () => {
  expect(checkPosture({ merged: {}, policy: {} }, 'barmkin-shim', []).some((w) => w.includes('disableSkillShellExecution'))).toBe(true)
  expect(
    checkPosture({ merged: { disableSkillShellExecution: false }, policy: {} }, 'barmkin-shim', []).some((w) =>
      w.includes('disableSkillShellExecution'),
    ),
  ).toBe(true)
})

test('does not warn when disableSkillShellExecution is true', () => {
  const warnings = checkPosture({ merged: { disableSkillShellExecution: true }, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('disableSkillShellExecution'))).toBe(false)
})

test('warns when the mcp server allowlist is empty', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-shim', [])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(true)
})

test('does not warn when the mcp server allowlist is set', () => {
  const warnings = checkPosture({ merged: {}, policy: {} }, 'barmkin-shim', ['github', 'linear'])
  expect(warnings.some((w) => w.includes('mcp_server_allowlist'))).toBe(false)
})

test('a fully hardened posture produces no warnings', () => {
  const warnings = checkPosture(GOOD_SEAT, 'barmkin-shim', ['github'])
  expect(warnings).toEqual([])
})

test('a failed policy read reports seating as unverified and still runs the merged checks', () => {
  const warnings = checkPosture({ merged: {}, policy: null }, 'barmkin-shim', ['github'])
  expect(warnings.some((w) => w.includes('seating unverified'))).toBe(true)
  expect(warnings.some((w) => w.includes('is not in managed prependPlugins'))).toBe(false)
  expect(warnings.some((w) => w.includes('Bash sandbox is off'))).toBe(true)
})

test('a failed merged read reports its checks as unverified and still checks seating', () => {
  const warnings = checkPosture({ merged: null, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-shim@acme'] } }, 'barmkin-shim', ['github'])
  expect(warnings.some((w) => w.includes('unverified'))).toBe(true)
  expect(warnings.some((w) => w.includes('Bash sandbox is off'))).toBe(false)
  expect(warnings.some((w) => w.includes('sec-default is seated ahead'))).toBe(true)
})

test('every warning is a single terminal-safe line that states a fix', () => {
  const all = [
    ...checkPosture({ merged: { permissions: { defaultMode: 'bypassPermissions' } }, policy: {} }, 'barmkin-shim', []),
    ...checkPosture({ merged: null, policy: { prependPlugins: ['sec-default@builtin', 'barmkin-shim@acme'] } }, 'barmkin-shim', []),
    ...checkPosture({ merged: {}, policy: null }, 'barmkin-shim', []),
  ]
  expect(all.length).toBeGreaterThan(6)
  for (const w of all) {
    expect(w).not.toMatch(/[\n\r`\x1b]/)
    expect(w.length).toBeLessThan(150)
  }
})
