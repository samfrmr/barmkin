// Pure view logic for the guard's TUI half (W4). No JSX and no host imports,
// so it runs under `bun test` and the rendering in opencode/tui.tsx stays thin.
//
// What it decides: whether the guard is present (from the plugin inventory,
// which is the only seat evidence the TUI has: re-scout V18, V35), what level
// of assurance to show, which lines to print, and when a change deserves a
// toast. It never invents protection: a guard that is loaded but not
// reporting is shown as exactly that.

import { GUARD_PLUGIN_ID, type StatusReport } from './status-rpc'

// The subset of `PluginInfo` (client plugin.list) this module reads.
export interface PluginEntryLike {
  readonly id?: string
  readonly source: { readonly type: string; readonly path?: string; readonly target?: string }
  readonly state: { readonly status: string; readonly error?: string }
}

export type Presence = 'active' | 'failed' | 'absent'
export type Level = 'ok' | 'degraded' | 'unguarded'

export interface Inventory {
  presence: Presence
  error?: string
}

// PluginState in the 2.0.27 client types (packages/client/src/promise/generated/types.ts)
// is { status: 'active' } | { status: 'failed'; error: string; ref?: string }, so
// 'active' is the only live status and anything else is treated as not live.

// An inventory entry for the guard is matched by plugin id. A plugin that
// failed before its module was read has no id, so a failed entry is also
// matched by its source path or package name containing the guard id.
export function guardInventory(plugins: readonly PluginEntryLike[] | undefined, guardId: string = GUARD_PLUGIN_ID): Inventory {
  if (!plugins) return { presence: 'absent' }
  const matches = plugins.filter((plugin) => {
    if (plugin.id === guardId) return true
    if (plugin.state.status === 'active') return false
    const where = plugin.source.path ?? plugin.source.target ?? ''
    return where.includes(guardId)
  })
  if (matches.length === 0) return { presence: 'absent' }
  const failed = matches.find((plugin) => plugin.state.status !== 'active')
  if (failed) return { presence: 'failed', error: firstLine(failed.state.error) ?? 'plugin status: ' + failed.state.status }
  return { presence: 'active' }
}

function firstLine(text: string | undefined): string | undefined {
  const line = text?.split('\n').find((l) => l.trim().length > 0)
  return line?.trim().slice(0, 200)
}

export interface ViewInput {
  inventory: Inventory
  report?: StatusReport
  // Why there is no report ("rpc.unavailable: ..."), when there is none.
  reportError?: string
}

export interface View {
  level: Level
  // One short token for the prompt footer.
  chip: string
  // One short line for the sidebar title and the banner.
  headline: string
  // The sidebar and dialog body, in order. Contract text first, verbatim.
  lines: string[]
  // Set when the composer-top slot should show a banner.
  banner?: string
  // Identity used to decide whether a change deserves a toast.
  seatKey: string
  seatLabel: string
}

function seatLabelOf(report: StatusReport | undefined): string {
  if (!report) return 'unknown'
  return report.seat.label ?? report.seat.kind
}

// The barmkin monitor holds every session's taint and decides every call, so
// a monitor the server half could not reach means every guarded call is denied.
function monitorProblem(report: StatusReport): string | undefined {
  const state = report.monitor?.state
  if (state === undefined || state === 'ok') return undefined
  return 'barmkin monitor: ' + state + ', so guarded tool calls are denied'
}

function mcpProblem(report: StatusReport): string | undefined {
  const mcp = report.mcp
  if (!mcp) return undefined
  const missing = Object.entries(mcp.installed)
    .filter(([, ok]) => !ok)
    .map(([name]) => name)
  if (missing.length > 0) return 'MCP guard not fully installed (' + missing.join(', ') + ')'
  if (mcp.errors.length > 0) return 'MCP guard reported ' + mcp.errors.length + ' error' + (mcp.errors.length === 1 ? '' : 's') + ': ' + mcp.errors[mcp.errors.length - 1]
  return undefined
}

function mcpLine(report: StatusReport): string | undefined {
  const mcp = report.mcp
  if (!mcp) return undefined
  const scope = mcp.allowlistActive ? 'allowlist of ' + mcp.allowlist.length + ' server' + (mcp.allowlist.length === 1 ? '' : 's') : 'no allowlist (audit only)'
  const parts = [
    mcp.neutralised.descriptions + ' description' + (mcp.neutralised.descriptions === 1 ? '' : 's') + ' neutralised',
    mcp.hiddenTools.length + ' tool' + (mcp.hiddenTools.length === 1 ? '' : 's') + ' hidden',
    mcp.deniedCalls + ' call' + (mcp.deniedCalls === 1 ? '' : 's') + ' refused',
  ]
  const lines = ['MCP guard: ' + scope + '; ' + parts.join(', ') + '.']
  if (mcp.removedServers.length > 0) lines.push('Dropped at source: ' + mcp.removedServers.join(', ') + '.')
  if (mcp.unclassifiedNamespaces.length > 0) lines.push('Not screened (namespaces the guard does not know as MCP servers): ' + mcp.unclassifiedNamespaces.join(', ') + '.')
  return lines.join(' ')
}

export function buildView(input: ViewInput): View {
  const { inventory, report } = input

  if (inventory.presence !== 'active') {
    const failed = inventory.presence === 'failed'
    const headline = failed ? 'barmkin-opencode FAILED: this session is UNGUARDED' : 'barmkin-opencode is ABSENT: this session is UNGUARDED'
    return {
      level: 'unguarded',
      chip: failed ? '🏰 guard FAILED' : '🏰 guard ABSENT',
      headline,
      lines: [
        headline,
        ...(inventory.error ? ['Load error: ' + inventory.error] : []),
        'No posture line means no guard. Nothing is being redacted, screened or gated by barmkin-opencode.',
      ],
      banner: headline,
      seatKey: inventory.presence,
      seatLabel: inventory.presence,
    }
  }

  if (!report) {
    const headline = 'barmkin-opencode is loaded but not reporting its posture'
    return {
      level: 'degraded',
      chip: '🏰 guard ?',
      headline,
      lines: [
        headline,
        ...(input.reportError ? ['Status call failed: ' + input.reportError] : []),
        'The plugin inventory lists the guard, but the guard did not answer, so its posture, seat and taint are unknown.',
      ],
      banner: headline,
      seatKey: 'active:unreported',
      seatLabel: 'unknown',
    }
  }

  const problem = monitorProblem(report) ?? mcpProblem(report)
  const level: Level = problem || report.conditionalLines.length > 0 ? 'degraded' : 'ok'
  const taint = report.taint
  const lines = [report.postureLine, ...report.conditionalLines]
  lines.push('Seat: ' + seatLabelOf(report) + (report.seat.repoCanUnload === true ? ' (a repository config can unload this guard)' : '') + '.')
  // The taint is sticky: nothing lowers it, and only a new session starts clean.
  lines.push(taint.tainted ? 'Session taint: TAINTED' + (taint.sensitive ? ' (sensitive)' : '') + (taint.reason ? ' - ' + taint.reason : '') + '. It holds until the session ends.' : 'Session taint: none.')
  const mcp = mcpLine(report)
  if (mcp) lines.push(mcp)
  if (problem) lines.push(problem + '.')

  let banner: string | undefined
  if (problem) banner = 'barmkin-opencode: ' + problem
  else if (taint.tainted) banner = 'barmkin-opencode: session tainted, outward-effect tools are refused' + (taint.reason ? ' (' + taint.reason + ')' : '')

  return {
    level,
    chip: '🏰 ' + (taint.tainted ? 'TAINTED' : level === 'ok' ? 'barmkin' : 'barmkin !'),
    headline: taint.tainted ? 'barmkin-opencode: session tainted' : 'barmkin-opencode ' + report.version,
    lines,
    banner,
    seatKey: 'active:' + report.seat.kind,
    seatLabel: seatLabelOf(report),
  }
}

export interface ToastSpec {
  variant: 'info' | 'warning' | 'error'
  title: string
  message: string
}

// A toast for a change in guard presence or seat, or for a first sight that is
// not clean. Taint changes are not toasted here: the slots carry them.
export function toastFor(previous: View | undefined, next: View): ToastSpec | undefined {
  if (!previous) {
    if (next.level === 'ok') return undefined
    return { variant: next.level === 'unguarded' ? 'error' : 'warning', title: 'barmkin-opencode', message: next.headline }
  }
  if (previous.seatKey === next.seatKey) return undefined
  if (next.level === 'unguarded') return { variant: 'error', title: 'barmkin-opencode guard lost', message: next.headline }
  if (previous.level === 'unguarded') return { variant: 'info', title: 'barmkin-opencode guard back', message: 'Seat: ' + next.seatLabel + '.' }
  return { variant: 'warning', title: 'barmkin-opencode seat changed', message: previous.seatLabel + ' -> ' + next.seatLabel + '.' }
}

export function statusText(view: View): string {
  return view.lines.join('\n\n')
}
