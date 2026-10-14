// The real guard (server.ts) seated in the host model with the options a
// working deployment gives it, pointed at a monitor's socket.

import { loadGuard } from './contract-modules'
import { SeatHost, type HostInput, type PluginDef } from './seat-host'

export const GUARD = 'barmkin-opencode'

// What the guard needs to register its sessions: the operator's word that
// OpenCode's tools run in a sandbox that cannot reach the monitor socket.
export const SANDBOXED = { sandboxed: true }

export interface GuardHostInput {
  // A fresh copy of the guard module (an OpenCode restart); the shared one when omitted.
  instance?: string
  options?: Record<string, unknown>
  sessions?: HostInput['sessions']
  // Plugins after the guard, by id.
  after?: Record<string, PluginDef>
}

export async function guardHost(input: GuardHostInput = {}): Promise<SeatHost> {
  const after = input.after ?? {}
  return SeatHost.create({
    seats: { 'global-config': { plugins: [GUARD] }, 'config-file': { plugins: Object.keys(after) } },
    registry: { [GUARD]: (await loadGuard(input.instance)) as PluginDef, ...after },
    options: { [GUARD]: input.options ?? SANDBOXED },
    sessions: input.sessions,
  })
}

let sessions = 0
// A session id of the test's own: guard state may live at module level.
export function newSession(tag = 'ses'): string {
  return `${tag}_${process.pid}_${++sessions}`
}
