// The 'claude-code' module the shim imports, for the end-to-end host
// (host.ts): $.state atoms held by the host that loaded the shim.

export const STATE = Symbol.for('barmkin.e2e.state')

interface Atom<T> {
  id: { plugin: string; key: string }
  initial: T
}

export function atom<T>(id: { plugin: string; key: string }, initial: T): Atom<T> {
  return { id, initial }
}

function cells($: any): Map<string, unknown> {
  const held = $?.[STATE]
  if (!(held instanceof Map)) throw new Error('$.state is not available on this $')
  return held
}

export async function read<T>($: any, a: Atom<T>): Promise<T> {
  const held = cells($)
  const key = a.id.plugin + '/' + a.id.key
  return held.has(key) ? (held.get(key) as T) : a.initial
}

export async function update<T>($: any, a: Atom<T>, change: (current: T) => T): Promise<T> {
  const next = change(await read($, a))
  cells($).set(a.id.plugin + '/' + a.id.key, next)
  return next
}
