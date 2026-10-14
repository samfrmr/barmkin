// The TUI half's view of the server half's report: what it says about the
// monitor and the taint.

import { describe, expect, test } from 'bun:test'
import { buildView } from '../src/tui-view'
import type { StatusReport } from '../src/status-rpc'

const report = (over: Partial<StatusReport> = {}): StatusReport => ({
  version: '0.1.0',
  postureLine: 'posture',
  conditionalLines: [],
  seat: { kind: 'inline-config', label: 'inline config', repoCanUnload: false },
  taint: { tainted: false },
  monitor: { state: 'ok' },
  ...over,
})

describe('tui view', () => {
  test('a reachable monitor and an untainted session read as ok', () => {
    const view = buildView({ inventory: { presence: 'active' }, report: report() })
    expect(view.level).toBe('ok')
    expect(view.lines).toContain('Session taint: none.')
  })

  test('a monitor the server half could not reach degrades the view and says calls are denied', () => {
    const view = buildView({ inventory: { presence: 'active' }, report: report({ monitor: { state: 'unavailable' } }) })
    expect(view.level).toBe('degraded')
    expect(view.banner).toContain('barmkin monitor: unavailable, so guarded tool calls are denied')
  })

  test('a tainted session says the taint holds until the session ends', () => {
    const view = buildView({ inventory: { presence: 'active' }, report: report({ taint: { tainted: true, reason: 'a web fetch or search result' } }) })
    expect(view.chip).toContain('TAINTED')
    expect(view.lines.join('\n')).toContain('It holds until the session ends.')
  })
})
