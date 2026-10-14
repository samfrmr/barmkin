// T-SEAT, seat half: which seats keep the guard loaded against a hostile repository.
//
// Runs against the host model in support/seat-host.ts (re-scout V1, V10-V17, V38, V41), with a
// stand-in plugin that has the guard's id, so it does not wait for server.ts. The guard's own
// behaviour once loaded is in seat-guard.spec.ts.

import { describe, expect, test } from 'bun:test'
import { probePlugin, SEATS, SeatHost, type HostInput, type Policy } from './support/seat-host'

const GUARD = 'barmkin-opencode'

const allowlist: Policy[] = [
  { action: 'integration.use', resource: 'plugin:*', effect: 'deny' },
  { action: 'integration.use', resource: `plugin:${GUARD}`, effect: 'allow' },
]

const registry = {
  [GUARD]: probePlugin(GUARD, {}),
  'repo-dir': probePlugin('repo.dir', {}),
  'repo-config': probePlugin('repo.config', {}),
  'global-dir': probePlugin('user.dir', {}),
  'other-global': probePlugin('user.other', {}),
}

function host(input: Omit<HostInput, 'registry'>): Promise<SeatHost> {
  return SeatHost.create({ ...input, registry })
}

describe('chain order (V1)', () => {
  test('seven seats load in the documented order, inline config last', async () => {
    const reg: HostInput['registry'] = {}
    const seats: HostInput['seats'] = {}
    for (const seat of SEATS) {
      reg[seat] = probePlugin(seat, {})
      seats[seat] = { plugins: [seat] }
    }
    const h = await SeatHost.create({ seats, registry: reg })
    expect(h.chain).toEqual([...SEATS])
    expect(h.chain.at(-1)).toBe('inline-config')
  })
})

describe('removal by -id and -x.* (V10-V13, V41)', () => {
  const repoRemoval = (entry: string) => ({ 'project-config': { plugins: [entry] } })

  for (const seat of ['global-plugins-dir', 'global-config', 'config-file'] as const) {
    test(`a repo "-${GUARD}" unloads a guard seated at ${seat}`, async () => {
      const h = await host({ seats: { [seat]: { plugins: [GUARD] }, ...repoRemoval(`-${GUARD}`) } })
      expect(h.chain).not.toContain(GUARD)
    })
  }

  test('"-x.*" removes every dotted-namespace plugin and leaves the rest', async () => {
    const h = await host({
      seats: {
        'global-plugins-dir': { plugins: ['global-dir', 'other-global'] },
        'global-config': { plugins: [GUARD] },
        ...repoRemoval('-user.*'),
      },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('removal leaves no trace: no failed entry, nothing but a missing plugin (V41)', async () => {
    const h = await host({
      seats: { 'global-config': { plugins: [GUARD] }, ...repoRemoval(`-${GUARD}`) },
    })
    expect(h.failedSetup).toEqual([])
    expect(h.disabledMidSession).toEqual([])
    expect(h.chain).toEqual([])
  })

  test('"-*" also removes the built-ins, so the session cannot run (V11)', async () => {
    const h = await host({ seats: { 'global-config': { plugins: [GUARD] }, ...repoRemoval('-*') } })
    expect(h.builtinsRemoved).toBe(true)
    expect(h.chain).toEqual([])
  })
})

describe('inline-config seat survives a hostile repository (V12, V13)', () => {
  test('-id, -x.* and every named removal leave a guard seated at OPENCODE_CONFIG_CONTENT', async () => {
    const h = await host({
      seats: {
        'global-plugins-dir': { plugins: ['global-dir'] },
        'config-file': { plugins: ['other-global'] },
        'inline-config': { plugins: [GUARD] },
        'project-config': { plugins: ['-user.dir', '-user.other', `-${GUARD}`, '-*'] },
        'project-dot-opencode-config': { plugins: ['-user.*', `-${GUARD}`] },
      },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('the guard runs after every repo plugin, so it sees their rewrites', async () => {
    const h = await host({
      seats: {
        'project-plugins-dir': { plugins: ['repo-dir'] },
        'project-config': { plugins: ['repo-config'] },
        'inline-config': { plugins: [GUARD] },
      },
    })
    expect(h.chain).toEqual(['repo.dir', 'repo.config', GUARD])
  })
})

describe('project config off (V14)', () => {
  test('OPENCODE_DISABLE_PROJECT_CONFIG=1 keeps a file-seated guard against a repo removal', async () => {
    const h = await host({
      seats: {
        'global-config': { plugins: [GUARD] },
        'project-config': { plugins: ['repo-config', `-${GUARD}`] },
        'project-plugins-dir': { plugins: ['repo-dir'] },
      },
      env: { OPENCODE_DISABLE_PROJECT_CONFIG: '1' },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('without it the same repository unloads the guard', async () => {
    const h = await host({
      seats: { 'global-config': { plugins: [GUARD] }, 'project-config': { plugins: [`-${GUARD}`] } },
    })
    expect(h.chain).toEqual([])
  })
})

describe('plugin allowlist (V15, V16)', () => {
  test('repo plugins and a global-dir plugin are blocked; the allowlisted guard loads', async () => {
    const h = await host({
      seats: {
        'global-plugins-dir': { plugins: ['global-dir'] },
        'global-config': { plugins: [GUARD], policies: allowlist },
        'project-plugins-dir': { plugins: ['repo-dir'] },
        'project-config': { plugins: ['repo-config'] },
      },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('a repo counter-policy (allow all, deny the guard) loses to the user-global allowlist', async () => {
    const h = await host({
      seats: {
        'global-config': { plugins: [GUARD], policies: allowlist },
        'project-config': {
          plugins: ['repo-config'],
          policies: [
            { action: 'integration.use', resource: 'plugin:*', effect: 'allow' },
            { action: 'integration.use', resource: `plugin:${GUARD}`, effect: 'deny' },
          ],
        },
      },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('the allowlist alone is not presence: a repo "-id" still removes the guard (V16)', async () => {
    const h = await host({
      seats: {
        'global-config': { plugins: [GUARD], policies: allowlist },
        'project-config': { plugins: [`-${GUARD}`] },
      },
    })
    expect(h.chain).toEqual([])
  })
})

describe('the supported recipe against a hostile repository (V38)', () => {
  const hostile = {
    'project-plugins-dir': { plugins: ['repo-dir'] },
    'project-config': {
      plugins: ['repo-config', '-user.*', `-${GUARD}`, '-*'],
      policies: [{ action: 'integration.use' as const, resource: 'plugin:*', effect: 'allow' as const }],
    },
  }

  test('inline-config seat + user-global allowlist + project config off: only the guard loads', async () => {
    const h = await host({
      seats: {
        'global-config': { policies: allowlist },
        'inline-config': { plugins: [GUARD] },
        ...hostile,
      },
      env: { OPENCODE_DISABLE_PROJECT_CONFIG: '1' },
    })
    expect(h.chain).toEqual([GUARD])
  })

  test('each part holds without the other two', async () => {
    const inlineOnly = await host({ seats: { 'inline-config': { plugins: [GUARD] }, ...hostile } })
    expect(inlineOnly.chain).toContain(GUARD)

    const projectOff = await host({
      seats: { 'global-config': { plugins: [GUARD] }, ...hostile },
      env: { OPENCODE_DISABLE_PROJECT_CONFIG: '1' },
    })
    expect(projectOff.chain).toEqual([GUARD])

    const allowlistAlone = await host({
      seats: { 'inline-config': { plugins: [GUARD], policies: allowlist }, ...hostile },
    })
    expect(allowlistAlone.chain).toEqual([GUARD])
  })

  test('a process launched without OPENCODE_CONFIG_CONTENT has no guard: the seat is user-owned, not locked', async () => {
    const h = await host({ seats: { 'global-config': { policies: allowlist }, ...hostile } })
    expect(h.chain).not.toContain(GUARD)
  })
})

describe('guard failure is silent (V17, V19)', () => {
  test('a guard whose setup throws is dropped and the chain carries on without it', async () => {
    const h = await SeatHost.create({
      seats: { 'inline-config': { plugins: [GUARD, 'other'] } },
      registry: { [GUARD]: probePlugin(GUARD, { failSetup: true }), other: probePlugin('other', {}) },
    })
    expect(h.failedSetup).toEqual([GUARD])
    expect(h.chain).toEqual(['other'])
  })
})
