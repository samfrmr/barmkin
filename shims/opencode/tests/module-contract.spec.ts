// T-SEAT, module half: the files the OpenCode 2.x port contract names exist at their paths and
// import cleanly. Each one is owned by another worker, so a missing file skips its test here;
// BARMKIN_CONTRACT_STRICT=1 (integration and release runs) turns a missing file into a failure.

import { describe, expect, test } from 'bun:test'
import { CONTRACT_PATHS, loadModule, modulePresent, STRICT, type ContractModule } from './support/contract-modules'

const modules = Object.keys(CONTRACT_PATHS) as ContractModule[]

describe('contract modules', () => {
  for (const name of modules) {
    const path = `opencode/${CONTRACT_PATHS[name]}`
    const run = STRICT || modulePresent(name) ? test : test.skip

    run(`${path} exists and imports without side effects that throw`, async () => {
      expect(modulePresent(name)).toBe(true)
      if (name === 'serverTui') {
        // OpenCode compiles tui.tsx with its own Solid JSX runtime, so plain Bun cannot import it.
        return
      }
      const mod = await loadModule(name)
      expect(Object.keys(mod).length).toBeGreaterThan(0)
    })
  }

  test('server.ts is a Promise-API definition, not the 1.x default-exported function', async () => {
    if (!STRICT && !modulePresent('server')) return
    const mod = await loadModule('server')
    expect(typeof mod.default).toBe('object')
    expect(mod.default.id).toBe('barmkin-opencode')
    expect(typeof mod.default.setup).toBe('function')
  })
})
