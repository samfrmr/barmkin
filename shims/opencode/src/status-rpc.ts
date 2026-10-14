// The one channel between the guard's server half and its TUI half (W4).
//
// The server adapter registers this definition (`ctx.rpc.register(statusRpc,
// { status })`) and emits `changed` when the seat, the taint or the MCP guard
// state moves; the TUI (opencode/tui.tsx) calls `status` and listens for
// `changed`. The posture line travels as finished text, composed once by the
// server adapter, so the TUI renders the contract wording verbatim and never
// assembles it.
//
// A TUI that cannot reach this RPC says so ("loaded, not reporting"); it never
// guesses a posture. Plain data and JSON Schema only, no runtime imports, so
// the server bundle and the TUI module can both import it.

import type { McpGuardStatus } from './mcp-guard'

// The plugin id the server adapter exports (`export default { id, setup }`).
export const GUARD_PLUGIN_ID = 'barmkin-opencode'
export const STATUS_RPC_ID = 'barmkin-opencode.status'

export interface SeatReport {
  // Free-form so the server adapter can add seats without a TUI release;
  // known values are shown by their `label`, else the raw kind.
  kind: string
  label?: string
  // True when a repository's own config can unload the guard from this seat.
  repoCanUnload?: boolean
}

export interface TaintReport {
  tainted: boolean
  sensitive?: boolean
  reason?: string
}

// The barmkin monitor as the server half last found it: 'ok', or why its
// last request failed (src/monitor `Failure`).
export interface MonitorReport {
  state: string
}

export interface StatusReport {
  version: string
  // The contract "Posture line", verbatim.
  postureLine: string
  // The conditional lines that follow it, one per condition, verbatim.
  conditionalLines: string[]
  seat: SeatReport
  taint: TaintReport
  monitor?: MonitorReport
  mcp?: McpGuardStatus
}

export const statusRpc = {
  id: STATUS_RPC_ID,
  methods: {
    status: {
      input: { type: 'object' },
      output: {
        type: 'object',
        required: ['version', 'postureLine', 'conditionalLines', 'seat', 'taint'],
        properties: {
          version: { type: 'string' },
          postureLine: { type: 'string' },
          conditionalLines: { type: 'array', items: { type: 'string' } },
          seat: {
            type: 'object',
            required: ['kind'],
            properties: { kind: { type: 'string' }, label: { type: 'string' }, repoCanUnload: { type: 'boolean' } },
          },
          taint: {
            type: 'object',
            required: ['tainted'],
            properties: { tainted: { type: 'boolean' }, sensitive: { type: 'boolean' }, reason: { type: 'string' } },
          },
          monitor: { type: 'object', required: ['state'], properties: { state: { type: 'string' } } },
          mcp: { type: 'object' },
        },
      },
    },
  },
  events: {
    changed: {
      schema: { type: 'object', properties: { reason: { type: 'string' } } },
    },
  },
} as const

export function isStatusReport(value: unknown): value is StatusReport {
  if (value === null || typeof value !== 'object') return false
  const v = value as Record<string, unknown>
  const seat = v.seat as Record<string, unknown> | null | undefined
  const taint = v.taint as Record<string, unknown> | null | undefined
  return (
    typeof v.version === 'string' &&
    typeof v.postureLine === 'string' &&
    Array.isArray(v.conditionalLines) &&
    v.conditionalLines.every((line) => typeof line === 'string') &&
    seat !== null &&
    typeof seat === 'object' &&
    typeof seat.kind === 'string' &&
    taint !== null &&
    typeof taint === 'object' &&
    typeof taint.tainted === 'boolean'
  )
}
