// Monitors for the suite, on real Unix sockets, so the guard's own transport
// (src/monitor.ts, Bun `fetch` with `unix`) carries every request.
//
//   startFakeMonitor  the Claude Code shim's in-memory monitor
//                     (plugins/claude-code/barmkin-shim/tests/support), served
//                     over a socket. It decodes every request strictly and
//                     answers with the monitor's behaviour.
//   RealMonitor       a `barmkin monitor` process (BARMKIN_TEST_BIN), in a
//                     deployment laid out the way internal/monitor checks it.

import { mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { FakeMonitor, type FakeMonitorOptions } from '../../../../plugins/claude-code/barmkin-shim/tests/support/fake-monitor.ts'

export { FakeMonitor }

export const SOCKET_ENV = 'BARMKIN_MONITOR_SOCKET'

// A directory whose paths fit in a Unix socket address (108 bytes).
export function socketDir(): string {
  let dir = mkdtempSync(join(tmpdir(), 'bmk-'))
  if (dir.length > 80) {
    rmSync(dir, { recursive: true, force: true })
    dir = mkdtempSync('/tmp/bmk-')
  }
  return dir
}

export interface ServedFake {
  fake: FakeMonitor
  socket: string
  // Stops answering: the socket refuses connections until start.
  stop(): void
  start(): void
  // While set, every request is left unanswered.
  hang: boolean
  close(): void
}

export function startFakeMonitor(opts: FakeMonitorOptions = {}): ServedFake {
  const dir = socketDir()
  const socket = join(dir, 'monitor.sock')
  const fake = new FakeMonitor(opts)
  let server: ReturnType<typeof Bun.serve> | null = null
  const served: ServedFake = {
    fake,
    socket,
    hang: false,
    start() {
      if (server) return
      server = Bun.serve({
        unix: socket,
        fetch: async (req) => {
          if (served.hang) return new Promise<Response>(() => {})
          const reply = fake.handle(req.url, await req.text())
          return new Response(reply.text, { status: reply.status, headers: { 'content-type': 'application/json' } })
        },
      })
    },
    stop() {
      server?.stop(true)
      server = null
      rmSync(socket, { force: true })
    },
    close() {
      served.stop()
      rmSync(dir, { recursive: true, force: true })
    },
  }
  served.start()
  return served
}

// A real `barmkin monitor`, started and killed by the test.
export class RealMonitor {
  readonly dir: string
  readonly socket: string
  private proc: ReturnType<typeof Bun.spawn> | null = null
  log = ''

  constructor(readonly bin: string) {
    this.dir = socketDir()
    mkdirSync(join(this.dir, 'run'), { mode: 0o750 })
    mkdirSync(join(this.dir, 'state'), { mode: 0o700 })
    this.socket = join(this.dir, 'run', 'monitor.sock')
  }

  async start(): Promise<void> {
    const group = Bun.spawnSync(['id', '-gn']).stdout.toString().trim()
    this.proc = Bun.spawn([this.bin, 'monitor', '-socket', this.socket, '-state-dir', join(this.dir, 'state'), '-client-group', group], {
      stdout: 'ignore',
      stderr: 'pipe',
    })
    void new Response(this.proc.stderr as ReadableStream).text().then((text) => (this.log += text))
    for (let i = 0; i < 200; i++) {
      try {
        const res = await fetch('http://barmkin/v1/health', { method: 'POST', body: '{"version":1}', unix: this.socket } as RequestInit)
        if (res.status === 200) return
      } catch {
        // not up yet
      }
      if (this.proc.exitCode !== null) break
      await Bun.sleep(25)
    }
    throw new Error('barmkin monitor did not start:\n' + this.log)
  }

  // SIGKILL: an unclean stop, so the next start raises monitor_restart.
  async kill(): Promise<void> {
    this.proc?.kill('SIGKILL')
    await this.proc?.exited
    this.proc = null
  }

  // SIGTERM: a clean stop, journaled.
  async stop(): Promise<void> {
    this.proc?.kill('SIGTERM')
    await this.proc?.exited
    this.proc = null
  }

  async close(): Promise<void> {
    await this.kill()
    rmSync(this.dir, { recursive: true, force: true })
  }
}
