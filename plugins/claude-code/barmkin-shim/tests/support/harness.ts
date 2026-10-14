// The engine beneath the shim in its integration tests: a FakeMonitor behind
// $.http.fetch, the monitor socket in the environment, a sandboxed posture, a
// test session id, and a started session. `test` here wraps the kit's test,
// so each body runs against a fresh monitor it can inspect and steer.
import { mock, test as kitTest } from 'claude-code/testing'
import { FakeMonitor, type FakeMonitorOptions } from './fake-monitor.ts'
import { POLICY_PATH } from '../../hooks/lib/policy'

export const SOCKET = '/run/barmkin/monitor.sock'
export const SESSION = 'sess-test'

// The managed recipe's seat, as $.settings.read() answers it.
export const MERGED = { sandbox: { enabled: true }, disableSkillShellExecution: true }
export const POLICY = { prependPlugins: ['barmkin-shim@barmkin-local', 'cc-plugin-sec-default@builtin'] }

export interface World {
  monitor: FakeMonitor
  // What $.ui.log was given, in order.
  logs: string[]
  // What each fetch was sent over: the socket path, per request.
  sockets: (string | undefined)[]
  clock: ReturnType<typeof mock.clock>
  // The session $.session.id() answers; a test may change it (a /clear).
  session: { id: string }
  // Every path the shim asked $.fs about, in order.
  fsPaths: string[]
}

// The root policy file as $.fs reports it at POLICY_PATH. Every other path is
// missing, so no test reads the machine's own /etc.
export interface PolicyFile {
  text: string
  // A symbolic link at the path itself.
  isLink?: boolean
  // Where the path resolves; POLICY_PATH unless set. null: it resolves nowhere.
  realPath?: string | null
  kind?: 'file' | 'dir' | 'other'
  // A file that stats but cannot be read.
  unreadable?: boolean
}

export interface WorldOptions extends FakeMonitorOptions {
  // $.env.get's answers. Default: the monitor socket only.
  env?: Record<string, string | undefined>
  // $.settings.read()'s merged answer, or null for a read that fails.
  merged?: Record<string, unknown> | null
  // What $.session.messages() answers at session start. Default: nothing yet.
  messages?: unknown[]
  // Leave the session unstarted, as a test of the first request's register.
  noStart?: boolean
  options?: Record<string, unknown>
  // The root policy at POLICY_PATH. Default: no file.
  policy?: PolicyFile
}

type Body = ($: any, on: any, world: World) => unknown

// world installs the engine beneath the shim. It must run before the first
// call on $, which loads the plugin.
export function world(on: any, opts: WorldOptions = {}): World {
  const monitor = new FakeMonitor(opts)
  const logs: string[] = []
  const sockets: (string | undefined)[] = []
  const session = { id: SESSION }
  const env = opts.env ?? { BARMKIN_MONITOR_SOCKET: SOCKET }
  const clock = mock.clock(on)
  on('env.get', (_$: any, e: any) => ({ value: env[e.name] }))
  on('settings.read', (_$: any, e: any) => {
    if (e?.source === 'policy') return { value: POLICY }
    if (opts.merged === null) throw new Error('settings read refused')
    return { value: opts.merged ?? MERGED }
  })
  on('session.id', () => ({ value: session.id }))
  on('session.messages', () => ({ value: opts.messages ?? [] }))
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('ui.log', (_$: any, e: any) => {
    logs.push(typeof e === 'string' ? e : String(e?.text ?? e?.message ?? JSON.stringify(e)))
    return { value: undefined }
  })
  on('ui.notice', () => ({ value: undefined }))
  const fsPaths: string[] = []
  const policyAt = (path: string): PolicyFile | undefined => (path === POLICY_PATH ? opts.policy : undefined)
  on('fs.stat', (_$: any, e: any) => {
    fsPaths.push(e.path)
    const file = policyAt(e.path)
    if (!file) throw new Error('ENOENT: no such file or directory, stat ' + e.path)
    const realPath = file.realPath === undefined ? POLICY_PATH : file.realPath
    const stat = { kind: file.kind ?? 'file', size: new TextEncoder().encode(file.text).length, mtimeMs: 0, isLink: file.isLink ?? false }
    return { value: e.resolve && realPath !== null ? { ...stat, realPath } : stat }
  })
  on('fs.exists', (_$: any, e: any) => {
    fsPaths.push(e.path)
    return { value: policyAt(e.path) !== undefined }
  })
  on('fs.read', (_$: any, e: any) => {
    fsPaths.push(e.path)
    const file = policyAt(e.path)
    if (!file || file.unreadable) throw new Error('EACCES: permission denied, open ' + e.path)
    return { value: file.text }
  })
  on('http.fetch', async (_$: any, e: any) => {
    sockets.push(e.init?.socketPath)
    if (monitor.down) throw new Error('connect ECONNREFUSED ' + e.init?.socketPath)
    if (monitor.hang) await new Promise(() => {})
    const r = monitor.handle(e.url, e.init?.body ?? '')
    return { value: { ok: r.status >= 200 && r.status < 300, status: r.status, headers: { 'content-type': 'application/json' }, text: r.text } }
  })
  return { monitor, logs, sockets, clock, session, fsPaths }
}

// start fires session.start, as Claude Code does before any turn.
export async function start($: any): Promise<void> {
  await $.session.start({ cwd: '/proj', surface: null, isInteractive: false })
}

// started wraps the engine's `$` so the session starts (session.start fires)
// before the body's first call on it. The body still registers its own hooks
// first, as the kit requires: nothing calls $ until the body does.
function started($: any): any {
  let once: Promise<void> | null = null
  const ready = () => (once ??= start($))
  const out: any = {}
  for (const name of Object.getOwnPropertyNames($)) {
    const n = $[name]
    if (!n || typeof n !== 'object') {
      out[name] = n
      continue
    }
    const wrapped: any = {}
    for (const verb of Object.getOwnPropertyNames(n)) {
      const f = n[verb]
      wrapped[verb] =
        typeof f !== 'function' || (name === 'session' && verb === 'start') ? f : async (...args: unknown[]) => (await ready(), f.apply(n, args))
    }
    out[name] = wrapped
  }
  return out
}

export function test(name: string, ...rest: [Body] | [WorldOptions, Body]): void {
  const [opts, body] = rest.length === 1 ? [{} as WorldOptions, rest[0]] : rest
  kitTest(name, { options: opts.options }, async ($: any, on: any) => {
    const w = world(on, opts)
    return body(opts.noStart ? $ : started($), on, w)
  })
}

// statusText runs the status command and returns its text.
export async function statusText($: any): Promise<string> {
  const out = await $.command.run({ command: 'barmkin-status' })
  return String(out?.text ?? '')
}
