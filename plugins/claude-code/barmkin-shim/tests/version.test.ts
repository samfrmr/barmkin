import { expect, test } from 'claude-code/testing'
import { compareVersions, meetsMinimumVersion, MIN_CLAUDE_CODE_VERSION } from '../hooks/lib/version'

test('compareVersions compares numerically, not lexicographically', () => {
  expect(compareVersions('2.1.9', '2.1.10')).toBe(-1)
  expect(compareVersions('2.1.10', '2.1.9')).toBe(1)
  expect(compareVersions('2.1.287', '2.1.287')).toBe(0)
})

test('meetsMinimumVersion against the pinned floor', () => {
  expect(meetsMinimumVersion('2.1.283', MIN_CLAUDE_CODE_VERSION)).toBe(false)
  expect(meetsMinimumVersion('2.1.287', MIN_CLAUDE_CODE_VERSION)).toBe(true)
  expect(meetsMinimumVersion('2.2.0', MIN_CLAUDE_CODE_VERSION)).toBe(true)
  expect(meetsMinimumVersion('3.0.0', MIN_CLAUDE_CODE_VERSION)).toBe(true)
})
