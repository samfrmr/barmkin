// The startup posture line and its conditional lines, as emitted by buildPostureLines.

import { describe, expect, test } from 'bun:test'
import { buildPostureLines, type MonitorPosture, type Seat } from '../server'

const FIXED_PREFIX =
  '🏰 barmkin-opencode 0.1.0 (core abc1234) · partial port, not equivalent to barmkin-mod for Claude Code · ' +
  'OpenCode 2 has no administrator-locked plugin seat · not covered: '

const inlineSeat: Seat = { inventory: 'ok', name: 'inline-config', inlineSeated: true, projectConfigDisabled: true, others: [], failed: [] }
const fileSeat: Seat = { inventory: 'ok', name: 'file-or-package', inlineSeated: false, projectConfigDisabled: false, others: [], failed: [] }
const healthy: MonitorPosture = { sandboxed: true, socketConfigured: true, health: 'ok' }

describe('buildPostureLines', () => {
  test('first line starts with the fixed non-equivalence wording and names the seat as not administrator-enforced', () => {
    for (const seat of [inlineSeat, fileSeat]) {
      const [first] = buildPostureLines(seat, healthy, 'abc1234')
      expect(first.startsWith(FIXED_PREFIX)).toBe(true)
      expect(first).toContain(`seat "${seat.name}" is user-owned, not administrator-enforced`)
    }
  })

  test('an unsandboxed OpenCode gets the refusal line; sandboxed:true does not', () => {
    const unsandboxed = buildPostureLines(inlineSeat, { ...healthy, sandboxed: false }, 'abc1234')
    expect(unsandboxed.some((l) => l.includes('outside a sandbox') && l.includes('every guarded tool call is denied'))).toBe(true)
    const sandboxed = buildPostureLines(inlineSeat, healthy, 'abc1234')
    expect(sandboxed.some((l) => l.includes('outside a sandbox'))).toBe(false)
  })

  test('a seat that project config can unload warns; the inline seat with project config off does not', () => {
    expect(buildPostureLines(fileSeat, healthy, 'abc1234').some((l) => l.includes("repository's opencode.json can unload this guard"))).toBe(true)
    expect(buildPostureLines(inlineSeat, healthy, 'abc1234')).toHaveLength(1)
  })

  test('a missing monitor socket says every guarded call is denied', () => {
    const lines = buildPostureLines(inlineSeat, { ...healthy, socketConfigured: false }, 'abc1234')
    expect(lines.some((l) => l.includes('is not set, so every guarded tool call is denied'))).toBe(true)
  })

  test('a degraded monitor says every guarded call is denied', () => {
    const lines = buildPostureLines(inlineSeat, { ...healthy, health: 'degraded' }, 'abc1234')
    expect(lines.some((l) => l.includes('degraded') && l.includes('every guarded tool call is denied'))).toBe(true)
  })
})
