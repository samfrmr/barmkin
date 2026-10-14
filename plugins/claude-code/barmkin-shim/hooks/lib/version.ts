// Mods require Claude Code >= 2.1.287 (no manifest field exists for a
// version floor as of this writing; the documented convention is to state
// it in the README and check at runtime). This compares dotted version
// strings numerically, not lexicographically, so "2.1.9" < "2.1.10".
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0)
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0)
  const len = Math.max(pa.length, pb.length)
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (diff !== 0) return diff < 0 ? -1 : 1
  }
  return 0
}

export const MIN_CLAUDE_CODE_VERSION = '2.1.287'

export function meetsMinimumVersion(version: string, minimum: string = MIN_CLAUDE_CODE_VERSION): boolean {
  return compareVersions(version, minimum) >= 0
}
