// The OpenCode shim's reader for the root policy (src/policy-file.ts), against
// real files. The shim reads ROOT_POLICY_LOCATION alone; these run the same
// checks on a tree this test owns, with its own uid standing in for root.

import { afterAll, describe, expect, test } from 'bun:test'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { POLICY_PATH } from '../src/lib'
import { readPolicyAt, ROOT_POLICY_LOCATION, type PolicyLocation } from '../src/policy-file'
import { FULL_POLICY } from '../../../plugins/claude-code/barmkin-shim/tests/support/policy-fixtures.ts'

const roots: string[] = []
afterAll(() => {
  for (const r of roots) rmSync(r, { recursive: true, force: true })
})

const uid = process.getuid!()

// A fresh tree: <root>/etc/barmkin/policy.yaml, every directory 0755 and the file 0644.
function tree(text: string | null = FULL_POLICY): PolicyLocation & { root: string } {
  const root = mkdtempSync(join(tmpdir(), 'bmk-policy-'))
  roots.push(root)
  chmodSync(root, 0o755)
  const etc = join(root, 'etc')
  const dir = join(etc, 'barmkin')
  mkdirSync(dir, { recursive: true, mode: 0o755 })
  chmodSync(etc, 0o755)
  chmodSync(dir, 0o755)
  const file = join(dir, 'policy.yaml')
  if (text !== null) {
    writeFileSync(file, text)
    chmodSync(file, 0o644)
  }
  return { root, file, dirs: [root, etc, dir], owner: uid }
}

describe('readPolicyAt', () => {
  test('the shim reads /etc/barmkin/policy.yaml, owned by root, with root owning every directory above it', () => {
    expect(ROOT_POLICY_LOCATION).toEqual({ file: POLICY_PATH, dirs: ['/', '/etc', '/etc/barmkin'], owner: 0 })
    expect(POLICY_PATH).toBe('/etc/barmkin/policy.yaml')
  })

  test('reads a policy its owner alone can write', () => {
    expect(readPolicyAt(tree())).toEqual({ kind: 'file', text: FULL_POLICY })
  })

  test('a missing file, or a missing directory, is absent', () => {
    expect(readPolicyAt(tree(null))).toEqual({ kind: 'absent' })
    const t = tree(null)
    rmSync(join(t.root, 'etc'), { recursive: true })
    expect(readPolicyAt(t)).toEqual({ kind: 'absent' })
  })

  test('refuses a symbolic link, even to a good policy', () => {
    const t = tree()
    const real = join(t.root, 'real.yaml')
    writeFileSync(real, FULL_POLICY)
    rmSync(t.file)
    symlinkSync(real, t.file)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: 'it is a symbolic link' })
  })

  test('refuses a dangling symbolic link rather than reading it as absent', () => {
    const t = tree(null)
    symlinkSync(join(t.root, 'nowhere.yaml'), t.file)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: 'it is a symbolic link' })
  })

  test('refuses a linked directory above the file', () => {
    const t = tree()
    const elsewhere = join(t.root, 'elsewhere')
    mkdirSync(elsewhere, { mode: 0o755 })
    chmodSync(elsewhere, 0o755)
    writeFileSync(join(elsewhere, 'policy.yaml'), FULL_POLICY)
    chmodSync(join(elsewhere, 'policy.yaml'), 0o644)
    rmSync(join(t.root, 'etc', 'barmkin'), { recursive: true })
    symlinkSync(elsewhere, join(t.root, 'etc', 'barmkin'))
    const read = readPolicyAt(t)
    expect(read.kind).toBe('refused')
  })

  test('refuses a file others can write', () => {
    for (const mode of [0o664, 0o646, 0o666]) {
      const t = tree()
      chmodSync(t.file, mode)
      expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: 'it is writable by users other than uid ' + uid })
    }
  })

  test('refuses a directory above it that others can write', () => {
    const t = tree()
    chmodSync(t.dirs[2], 0o775)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: t.dirs[2] + ' is writable by users other than uid ' + uid })
    chmodSync(t.dirs[2], 0o755)
    chmodSync(t.dirs[1], 0o757)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: t.dirs[1] + ' is writable by users other than uid ' + uid })
  })

  test('refuses a file or directory that root does not own', () => {
    const t = tree()
    expect(readPolicyAt({ ...t, owner: uid + 1 })).toEqual({ kind: 'refused', reason: t.dirs[0] + ' is not owned by uid ' + (uid + 1) })
    expect(readPolicyAt({ ...t, dirs: [], owner: uid + 1 })).toEqual({ kind: 'refused', reason: 'it is not owned by uid ' + (uid + 1) })
  })

  test('refuses a directory, and a FIFO without blocking on it', () => {
    const t = tree(null)
    mkdirSync(t.file)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: 'it is not a regular file' })
    const f = tree(null)
    if (spawnSync('mkfifo', [f.file]).status === 0) {
      expect(readPolicyAt(f)).toEqual({ kind: 'refused', reason: 'it is not a regular file' })
    }
  })

  test('refuses a file over the size bound, and one that is not UTF-8', () => {
    expect(readPolicyAt(tree('version: 1\n' + '#'.repeat(70 * 1024)))).toEqual({ kind: 'refused', reason: 'it is larger than 65536 bytes' })
    const t = tree(null)
    writeFileSync(t.file, Buffer.from([0x76, 0x3a, 0x20, 0xff, 0xfe, 0x0a]))
    chmodSync(t.file, 0o644)
    expect(readPolicyAt(t)).toEqual({ kind: 'refused', reason: 'it is not UTF-8 text' })
  })
})
