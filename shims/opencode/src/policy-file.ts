// Reads the root policy (/etc/barmkin/policy.yaml; see the library's policy.ts)
// for the OpenCode shim. Node's file API shows what Claude Code's $.fs does
// not: owner and mode. So, beyond refusing a symbolic link, a path that
// resolves elsewhere and a file that is not regular, this refuses a policy
// that root does not own or that anyone else can write, and the same for every
// directory above it. The file is opened without following a link and checked
// again through its descriptor, so it cannot be swapped between the checks.
//
// The shim reads ROOT_POLICY_LOCATION only. readPolicyAt takes a location so
// the tests can run the same checks on a tree they own; nothing in the shim
// passes it any other.

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, type Stats } from 'node:fs'
import { MAX_POLICY_BYTES, POLICY_PATH, type PolicyRead } from './lib'

export interface PolicyLocation {
  // The policy file, as an absolute path with no link in it.
  file: string
  // Every directory above it, each of which must be the owner's alone.
  dirs: readonly string[]
  // The uid that must own the file and those directories.
  owner: number
}

export const ROOT_POLICY_LOCATION: PolicyLocation = { file: POLICY_PATH, dirs: ['/', '/etc', '/etc/barmkin'], owner: 0 }

export function readPolicyFile(): PolicyRead {
  return readPolicyAt(ROOT_POLICY_LOCATION)
}

const GROUP_OR_OTHER_WRITE = 0o022

function refused(reason: string): PolicyRead {
  return { kind: 'refused', reason }
}

function ownerName(uid: number): string {
  return uid === 0 ? 'root' : 'uid ' + uid
}

// Why `st` may not hold or lead to the policy, or null when it may.
function ownershipProblem(what: string, st: Stats, owner: number): string | null {
  if (st.uid !== owner) return what + ' is not owned by ' + ownerName(owner)
  if ((st.mode & GROUP_OR_OTHER_WRITE) !== 0) return what + ' is writable by users other than ' + ownerName(owner)
  return null
}

export function readPolicyAt(loc: PolicyLocation): PolicyRead {
  let link: Stats
  try {
    link = lstatSync(loc.file)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    return code === 'ENOENT' || code === 'ENOTDIR' ? { kind: 'absent' } : refused('it could not be inspected')
  }
  if (link.isSymbolicLink()) return refused('it is a symbolic link')
  if (!link.isFile()) return refused('it is not a regular file')

  for (const dir of loc.dirs) {
    let st: Stats
    try {
      st = lstatSync(dir)
    } catch {
      return refused(dir + ' could not be inspected')
    }
    if (st.isSymbolicLink()) return refused(dir + ' is a symbolic link')
    if (!st.isDirectory()) return refused(dir + ' is not a directory')
    const problem = ownershipProblem(dir, st, loc.owner)
    if (problem) return refused(problem)
  }
  try {
    if (realpathSync(loc.file) !== loc.file) return refused('its path does not resolve to ' + loc.file)
  } catch {
    return refused('its path could not be resolved')
  }

  let fd: number
  try {
    fd = openSync(loc.file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch {
    return refused('it could not be opened')
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile() || st.dev !== link.dev || st.ino !== link.ino) return refused('it changed while it was read')
    const problem = ownershipProblem('it', st, loc.owner)
    if (problem) return refused(problem)
    if (st.size > MAX_POLICY_BYTES) return refused('it is larger than ' + MAX_POLICY_BYTES + ' bytes')
    const buf = Buffer.alloc(MAX_POLICY_BYTES + 1)
    let length = 0
    for (;;) {
      const n = readSync(fd, buf, length, buf.length - length, null)
      if (n === 0) break
      length += n
      if (length > MAX_POLICY_BYTES) return refused('it is larger than ' + MAX_POLICY_BYTES + ' bytes')
    }
    try {
      return { kind: 'file', text: new TextDecoder('utf-8', { fatal: true }).decode(buf.subarray(0, length)) }
    } catch {
      return refused('it is not UTF-8 text')
    }
  } catch {
    return refused('it could not be read')
  } finally {
    closeSync(fd)
  }
}
