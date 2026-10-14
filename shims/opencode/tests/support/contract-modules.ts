// Loads the modules the OpenCode 2.x port contract names, by path, so this suite can land
// before the files do. A missing module skips the tests that need it; with
// BARMKIN_CONTRACT_STRICT=1 (the integration and release runs) a missing module fails instead.

import { existsSync } from 'node:fs'
import { join } from 'node:path'

export const OPENCODE_DIR = join(import.meta.dir, '..', '..')

export const CONTRACT_PATHS = {
  server: 'server.ts',
  resultShapes: 'src/result-shapes.ts',
  egressNormaliser: 'src/egress-normaliser.ts',
  mcpGuard: 'src/mcp-guard.ts',
  serverTui: 'tui.tsx',
} as const

export type ContractModule = keyof typeof CONTRACT_PATHS

export const STRICT = process.env.BARMKIN_CONTRACT_STRICT === '1'

export function modulePath(name: ContractModule): string {
  return join(OPENCODE_DIR, CONTRACT_PATHS[name])
}

export function modulePresent(name: ContractModule): boolean {
  return existsSync(modulePath(name))
}

// Tests that need a module are skipped while it is absent, unless the run is strict.
export function skipUnlessPresent(...names: ContractModule[]): boolean {
  return !STRICT && names.some((n) => !modulePresent(n))
}

export async function loadModule(name: ContractModule): Promise<Record<string, any>> {
  return (await import(modulePath(name))) as Record<string, any>
}

// The guard's module. With a tag, a copy of its own: a fresh module instance with
// none of another copy's state, as an OpenCode restart loads it.
export async function loadGuard(tag?: string): Promise<{ id: string; setup(ctx: any): unknown }> {
  const mod = (tag === undefined ? await loadModule('server') : await import(modulePath('server') + '?' + tag)) as Record<string, any>
  return mod.default
}
