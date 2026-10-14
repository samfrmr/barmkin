// A real `barmkin monitor` process and the real `barmkin gate`, for the
// end-to-end trust tests. BARMKIN_E2E_BIN names the barmkin binary
// (`make e2e` and CI build it).
//
// Each Monitor is its own deployment, laid out as the root-managed unit
// lays it out but for the current user: a runtime directory (0750) for the
// socket and a state directory (0700) for the journal, under a short path
// that fits a socket address.

import { execFileSync, spawn, type ChildProcess } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { createServer, request } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { opPath, type Op } from '../barmkin-shim/hooks/lib/proto.ts'

export const BIN = process.env.BARMKIN_E2E_BIN ?? ''
if (BIN === '') throw new Error('BARMKIN_E2E_BIN must name a barmkin binary: run `make e2e`')

const CLIENT_GROUP = execFileSync('id', ['-gn'], { encoding: 'utf8' }).trim()

export interface Reply {
  status: number
  text: string
}

// post sends one raw HTTP request over a Unix socket, as every client of the
// contract does. It rejects when nothing answers on the socket.
export function post(socketPath: string, path: string, body: string, method = 'POST'): Promise<Reply> {
  return new Promise((resolve, reject) => {
    const req = request(
      'http://barmkin' + path,
      { method, socketPath, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: 2000 },
      (res) => {
        let text = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => (text += chunk))
        res.on('end', () => resolve({ status: res.statusCode ?? 0, text }))
      },
    )
    req.on('timeout', () => req.destroy(new Error('timed out')))
    req.on('error', reject)
    req.end(body)
  })
}

export class Monitor {
  readonly base: string
  readonly socket: string
  readonly stateDir: string
  readonly ttl: string
  private proc: ChildProcess | null = null
  private exited: Promise<number | null> = Promise.resolve(null)
  private log = ''

  private constructor(ttl: string) {
    let base = mkdtempSync(join(tmpdir(), 'bme2e-'))
    if (base.length > 60) {
      rmSync(base, { recursive: true, force: true })
      base = mkdtempSync('/tmp/bme2e-')
    }
    this.base = base
    mkdirSync(join(base, 'run'), { mode: 0o750 })
    mkdirSync(join(base, 'state'), { mode: 0o700 })
    this.socket = join(base, 'run', 'monitor.sock')
    this.stateDir = join(base, 'state')
    this.ttl = ttl
  }

  // start lays out a new deployment and serves a monitor on it.
  static async start(opts: { ttl?: string } = {}): Promise<Monitor> {
    const m = new Monitor(opts.ttl ?? '10s')
    await m.serve()
    return m
  }

  // serve starts `barmkin monitor` on this deployment and waits until its
  // health answers ok.
  async serve(): Promise<void> {
    if (this.proc) throw new Error('monitor already running')
    const proc = spawn(
      BIN,
      ['monitor', '-socket', this.socket, '-state-dir', this.stateDir, '-client-group', CLIENT_GROUP, '-preregister-ttl', this.ttl],
      { stdio: ['ignore', 'ignore', 'pipe'] },
    )
    proc.stderr!.setEncoding('utf8')
    proc.stderr!.on('data', (chunk) => (this.log += chunk))
    this.exited = new Promise((resolve) => proc.on('exit', (code) => resolve(code)))
    this.proc = proc
    const until = Date.now() + 5000
    while (Date.now() < until) {
      if (proc.exitCode !== null) break
      try {
        const r = await post(this.socket, opPath('health'), '{"version":1}')
        if (r.status === 200 && JSON.parse(r.text).state === 'ok') return
      } catch {
        // not listening yet
      }
      await new Promise((r) => setTimeout(r, 25))
    }
    throw new Error('monitor did not come up:\n' + this.log)
  }

  // stop sends SIGTERM, which journals a clean stop, and returns the exit
  // code (0 for a clean stop).
  async stop(): Promise<number | null> {
    return this.signal('SIGTERM')
  }

  // kill sends SIGKILL: the monitor stops without journaling anything.
  async kill(): Promise<number | null> {
    return this.signal('SIGKILL')
  }

  private async signal(sig: NodeJS.Signals): Promise<number | null> {
    const proc = this.proc
    if (!proc) throw new Error('monitor not running')
    proc.kill(sig)
    const code = await this.exited
    this.proc = null
    return code
  }

  get pid(): number | undefined {
    return this.proc?.pid
  }

  get output(): string {
    return this.log
  }

  // send posts a raw body to an operation (or any path) of this monitor.
  send(op: Op | string, body: string, method = 'POST'): Promise<Reply> {
    return post(this.socket, op.startsWith('/') ? op : opPath(op as Op), body, method)
  }

  async close(): Promise<void> {
    if (this.proc) await this.kill()
    rmSync(this.base, { recursive: true, force: true })
  }
}

export interface GateResult {
  code: number | null
  reason: string | null
  stderr: string
}

// gate runs `barmkin gate` on one PreToolUse hook input, as the managed
// settings' PreToolUse hook does, and returns its exit code and the reason
// in its deny verdict.
export function gate(args: string[], input: string, env: Record<string, string> = {}): Promise<GateResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(BIN, ['gate', ...args], { stdio: ['pipe', 'ignore', 'pipe'], env: { PATH: process.env.PATH ?? '', ...env } })
    let stderr = ''
    proc.stderr.setEncoding('utf8')
    proc.stderr.on('data', (chunk) => (stderr += chunk))
    proc.on('error', reject)
    proc.on('exit', (code) => {
      const m = /"decision":"deny","reason":"([a-z-]+)"/.exec(stderr)
      resolve({ code, reason: m ? m[1] : null, stderr })
    })
    proc.stdin.end(input)
  })
}

// hookInput is the PreToolUse hook input Claude Code gives the gate.
export function hookInput(session: string, call: string, tool = 'Bash', input: Record<string, unknown> = { command: 'ls' }): string {
  return JSON.stringify({
    session_id: session,
    transcript_path: '/tmp/barmkin-e2e/' + session + '.jsonl',
    cwd: '/proj',
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: tool,
    tool_input: input,
    tool_use_id: call,
  })
}

// lowering stands up a faulty monitor in front of m, on its own socket: it
// forwards every request to m, but answers every operation that reports legs
// with them cleared, as a monitor that lowers a leg without the capability
// would. The tests that police tighten-only must fail against it.
export async function lowering(m: Monitor): Promise<{ socket: string; close: () => void }> {
  const socket = join(m.base, 'run', 'lowering.sock')
  const server = createServer((req, res) => {
    let body = ''
    req.setEncoding('utf8')
    req.on('data', (chunk) => (body += chunk))
    req.on('end', async () => {
      const r = await post(m.socket, req.url ?? '/', body, req.method)
      let text = r.text
      try {
        const parsed = JSON.parse(text)
        if (parsed.legs) text = JSON.stringify({ ...parsed, legs: { untrusted: 'none', sensitive: 'none' } })
      } catch {
        // an error answer carries no legs
      }
      res.writeHead(r.status, { 'content-type': 'application/json' }).end(text)
    })
  })
  await new Promise<void>((resolve) => server.listen(socket, resolve))
  return { socket, close: () => server.close() }
}
