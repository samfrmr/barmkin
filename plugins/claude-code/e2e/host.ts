// A stand-in for one Claude Code process running the barmkin shim, for the
// end-to-end trust tests. It loads the real hooks module
// (barmkin-shim/hooks/register.ts) and fires events through the hooks it
// registered, with $.http.fetch posting over the monitor's real Unix socket.
// For each tool call it does what Claude Code does under the managed
// settings (managed-settings.example.json): it appends the model's tool_use
// row (session.append, where the shim pre-registers the call), runs the
// managed PreToolUse hook (the real `barmkin gate`), and only if the gate
// exits 0 runs the call through tool.call.
//
// It models only the parts of the mods runtime the shim's hooks use: hook
// dispatch (the first hook registered is outermost, filters, .catch),
// $.state atoms, and the $ calls the shim makes. The shim's behaviour inside
// Claude Code itself is tested by `claude plugin test` and
// scripts/claude-lock-lab.sh; this host joins the shim's monitor transport to
// a real monitor and the real gate.

import { readFileSync } from 'node:fs'
import { request } from 'node:http'
import { registerHooks } from 'node:module'
import { randomUUID } from 'node:crypto'
import { STATE } from './claude-code.ts'
import { gate, hookInput, type GateResult } from './monitor.ts'

const SHIM = new URL('../barmkin-shim/hooks/register.ts', import.meta.url).href
const SHIM_DIR = new URL('../barmkin-shim/hooks/', import.meta.url).href
const KIT = new URL('./claude-code.ts', import.meta.url).href

// Claude Code resolves the hooks module's 'claude-code' import, and its own
// files imported without an extension; node needs telling.
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === 'claude-code') return { url: KIT, shortCircuit: true }
    try {
      return nextResolve(specifier, context)
    } catch (err: any) {
      if (err?.code !== 'ERR_MODULE_NOT_FOUND' || !specifier.startsWith('.') || !context.parentURL?.startsWith(SHIM_DIR)) throw err
      return nextResolve(specifier.replace(/\.js$/, '') + '.ts', context)
    }
  },
})

// The managed recipe, as $.settings.read() answers it: the merged settings
// and the policy source both carry it.
const RECIPE = JSON.parse(readFileSync(new URL('../managed-settings.example.json', import.meta.url), 'utf8'))
const CLAUDE_VERSION: string = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')).devDependencies['@anthropic-ai/claude-code']

type Handler = ($: any, e: any, next: any) => unknown
interface Hook {
  event: string
  filter: Record<string, unknown> | null
  handler: Handler
  onError: Handler | null
}

function matches(filter: Record<string, unknown> | null, e: any): boolean {
  if (!filter) return true
  return Object.entries(filter).every(([key, want]) => {
    const got = e?.[key]
    if (want instanceof RegExp) return typeof got === 'string' && want.test(got)
    if (Array.isArray(want)) return want.includes(got)
    return got === want
  })
}

interface FetchInit {
  method?: string
  headers?: Record<string, string>
  body?: string
  socketPath?: string
}

// $.http.fetch with socketPath: one HTTP exchange over the Unix socket. It
// rejects when nothing answers, as $.http.fetch does.
export function fetchOverSocket(url: string, init: FetchInit = {}): Promise<{ ok: boolean; status: number; headers: Record<string, string>; text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(url, { method: init.method ?? 'GET', headers: init.headers, socketPath: init.socketPath }, (res) => {
      let text = ''
      res.setEncoding('utf8')
      res.on('data', (chunk) => (text += chunk))
      res.on('end', () => {
        const status = res.statusCode ?? 0
        resolve({ ok: status >= 200 && status < 300, status, headers: res.headers as Record<string, string>, text })
      })
    })
    req.on('error', reject)
    req.end(init.body)
  })
}

export interface LaunchOptions {
  // The monitor socket the managed settings name: the gate's -socket, and the
  // shim's BARMKIN_MONITOR_SOCKET unless env says otherwise.
  socket: string
  // The shim's environment. Default: BARMKIN_MONITOR_SOCKET is socket.
  env?: Record<string, string | undefined>
  // Claude Code's session id. Default: a new one.
  session?: string
  // A resumed conversation: its transcript holds tool results, so it is not fresh.
  resumed?: boolean
  // false: the shim plugin is not loaded (not installed, disabled, or its hooks module failed to load).
  shim?: boolean
  // false: tools do not run in the sandbox, so the monitor refuses the session.
  sandboxed?: boolean
  // Extra flags for the managed gate, such as -monitor-uid.
  gateArgs?: string[]
  // Replaces the shim's transport. Default: one HTTP exchange over the socket.
  fetch?: typeof fetchOverSocket
  // The root policy's text at /etc/barmkin/policy.yaml, as $.fs answers it.
  // Default: no file. No other path exists, so no test reads the machine's /etc.
  policy?: string
}

const POLICY_PATH = '/etc/barmkin/policy.yaml'

export interface Use {
  call: string
  gate: GateResult
  // Whether the tool itself ran.
  ran: boolean
  // What tool.call answered: the tool's result, or the shim's deny.
  out?: any
}

let instances = 0

export class ClaudeCode {
  sessionId: string
  readonly logs: string[] = []
  private hooks: Hook[] = []
  private readonly env: Record<string, string | undefined>
  private readonly merged: Record<string, unknown>
  private readonly messages: unknown[]
  private readonly gateArgs: string[]
  readonly $: any

  private constructor(opts: LaunchOptions) {
    this.sessionId = opts.session ?? randomUUID()
    this.env = opts.env ?? { BARMKIN_MONITOR_SOCKET: opts.socket }
    this.merged = opts.sandboxed === false ? { ...RECIPE, sandbox: { ...RECIPE.sandbox, enabled: false } } : RECIPE
    this.messages = opts.resumed
      ? [
          { role: 'user', content: 'fetch the page' },
          { role: 'assistant', content: 'fetching' },
          { role: 'user', toolResults: [{ tool_use_id: 'toolu_earlier', content: 'page text' }] },
        ]
      : []
    this.gateArgs = ['-socket', opts.socket, ...(opts.gateArgs ?? [])]
    this.$ = {
      [STATE]: new Map(),
      env: { get: async (name: string) => this.env[name] },
      settings: { read: async (o?: { source?: string }) => (o?.source === 'policy' ? RECIPE : this.merged) },
      session: {
        id: async () => this.sessionId,
        messages: async () => this.messages,
        cwd: async () => '/proj',
        version: async () => CLAUDE_VERSION,
      },
      clock: {
        after: (ms: number, fn: () => void) => {
          const t = setTimeout(fn, ms)
          return { cancel: () => clearTimeout(t) }
        },
      },
      http: { fetch: opts.fetch ?? fetchOverSocket },
      ui: {
        log: (text: unknown) => void this.logs.push(String(text)),
        notice: () => undefined,
        status: () => undefined,
        resolve: () => undefined,
      },
      command: { register: async () => undefined },
      fs: {
        stat: async (path: string, o?: { resolve?: boolean }) => {
          if (path !== POLICY_PATH || opts.policy === undefined) throw new Error('ENOENT: no such file or directory, stat ' + path)
          const stat = { kind: 'file', size: Buffer.byteLength(opts.policy), mtimeMs: 0, isLink: false }
          return o?.resolve ? { ...stat, realPath: POLICY_PATH } : stat
        },
        exists: async (path: string) => path === POLICY_PATH && opts.policy !== undefined,
        read: async (path: string) => {
          if (path !== POLICY_PATH || opts.policy === undefined) throw new Error('ENOENT: no such file or directory, open ' + path)
          return opts.policy
        },
      },
    }
  }

  // launch starts a Claude Code process: it loads its own copy of the shim
  // (unless shim is false) and starts the session.
  static async launch(opts: LaunchOptions): Promise<ClaudeCode> {
    const cc = new ClaudeCode(opts)
    if (opts.shim !== false) {
      const mod = await import(SHIM + '?process=' + ++instances)
      mod.register(cc.on, {})
    }
    await cc.fire('session.start', { cwd: '/proj', surface: null, isInteractive: false }, (e) => ({ cwd: e.cwd }))
    return cc
  }

  private on = (event: string, ...rest: unknown[]) => {
    const handler = rest[rest.length - 1] as Handler
    const filter = rest.length > 1 ? (rest[0] as Record<string, unknown>) : null
    const hook: Hook = { event, filter, handler, onError: null }
    this.hooks.push(hook)
    return {
      catch(onError: Handler) {
        hook.onError = onError
      },
    }
  }

  // fire runs event through the hooks registered for it, outermost first,
  // down to bottom, which stands for Claude Code's own handling.
  fire(event: string, e: any, bottom: (e: any) => unknown): Promise<any> {
    const chain = this.hooks.filter((h) => h.event === event && matches(h.filter, e))
    const run = async (i: number, e: any): Promise<any> => {
      if (i === chain.length) return bottom(e)
      const hook = chain[i]
      const next = (e2: any) => run(i + 1, e2)
      try {
        return await hook.handler(this.$, e, next)
      } catch (err) {
        if (!hook.onError) throw err
        return hook.onError(this.$, e, Object.assign(next, { error: { kind: 'threw', message: String(err) } }))
      }
    }
    return run(0, e)
  }

  // append adds the model's assistant row with these tool_use blocks.
  async append(calls: { id: string; tool: string; input: Record<string, unknown> }[]): Promise<void> {
    const content = calls.map((c) => ({ type: 'tool_use', id: c.id, name: c.tool, input: c.input }))
    await this.fire('session.append', { message: { type: 'assistant', content } }, () => undefined)
  }

  // gate runs the managed PreToolUse hook on a call.
  gate(call: string, tool = 'Bash', input: Record<string, unknown> = { command: 'ls' }): Promise<GateResult> {
    return gate(this.gateArgs, hookInput(this.sessionId, call, tool, input))
  }

  // toolCall runs a call through tool.call; result is what the tool returns.
  async toolCall(call: string, tool: string, input: Record<string, unknown>, result: unknown): Promise<{ ran: boolean; out: any }> {
    let ran = false
    const out = await this.fire('tool.call', { tool, tool_use_id: call, ...input }, () => {
      ran = true
      return { result }
    })
    return { ran, out }
  }

  // use runs one tool call the model made, as Claude Code does: append its
  // tool_use row, run the managed gate, and run the call only if the gate
  // allowed it.
  async use(tool: string, input: Record<string, unknown>, result: unknown = 'ok'): Promise<Use> {
    const call = 'toolu_' + randomUUID().replaceAll('-', '')
    await this.append([{ id: call, tool, input }])
    const g = await this.gate(call, tool, input)
    if (g.code !== 0) return { call, gate: g, ran: false }
    const { ran, out } = await this.toolCall(call, tool, input, result)
    return { call, gate: g, ran, out }
  }

  // state reads one of the shim's $.state atoms.
  state(key: string): any {
    return this.$[STATE].get('barmkin-shim/' + key)
  }

  // clear starts a new session id in this process, as /clear does.
  clear(): void {
    this.sessionId = randomUUID()
  }

  // unloadShim drops the shim's hooks mid-session: the plugin was disabled or
  // its hooks module stopped loading.
  unloadShim(): void {
    this.hooks = []
  }
}
