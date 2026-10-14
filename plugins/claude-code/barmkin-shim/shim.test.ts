// Tests for the barmkin Claude Code shim. Run with: node --test shim.test.ts

import { test } from "node:test"
import assert from "node:assert/strict"
import { createServer, type IncomingMessage, type ServerResponse } from "node:http"
import { spawn } from "node:child_process"
import { mkdtempSync, rmSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { PassThrough } from "node:stream"
import { identity, interpret, readInput, register, PATH_REGISTER, VERSION } from "./shim.ts"

const SHIM = new URL("./shim.ts", import.meta.url).pathname

type Handler = (req: IncomingMessage, body: string, res: ServerResponse) => void

// fakeMonitor serves handler on a fresh Unix socket and records requests.
async function fakeMonitor(t: { after: (fn: () => void) => void }, handler: Handler) {
  const dir = mkdtempSync(join(tmpdir().length > 60 ? "/tmp" : tmpdir(), "bmk"))
  const socketPath = join(dir, "m.sock")
  const requests: string[] = []
  const server = createServer((req, res) => {
    let body = ""
    req.on("data", (c) => (body += c))
    req.on("end", () => {
      requests.push(`${req.method} ${req.url} ${body}`)
      handler(req, body, res)
    })
  })
  await new Promise<void>((resolve) => server.listen(socketPath, resolve))
  t.after(() => {
    server.closeAllConnections()
    server.close()
    rmSync(dir, { recursive: true, force: true })
  })
  return { socketPath, requests }
}

const ok: Handler = (_req, _body, res) => {
  res.writeHead(200, { "Content-Type": "application/json" })
  res.end(JSON.stringify({ version: 1, registered: true, reason: "ok" }))
}

function hookInput(session: unknown, call: unknown): string {
  return JSON.stringify({
    session_id: session,
    tool_use_id: call,
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: { command: "echo secret-content" },
  })
}

// runShim runs shim.ts as Claude Code would and returns its exit and output.
function runShim(input: string, env: Record<string, string | undefined>) {
  return new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    const child = spawn(process.execPath, [SHIM], { env: { PATH: process.env.PATH, ...env } })
    let stdout = ""
    let stderr = ""
    child.stdout.on("data", (c) => (stdout += c))
    child.stderr.on("data", (c) => (stderr += c))
    child.on("close", (code) => resolve({ code, stdout, stderr }))
    child.stdin.end(input)
  })
}

test("identity keeps only well-formed session and tool-call tokens", () => {
  assert.deepEqual(identity(hookInput("sess-a", "toolu_01A")), { session: "sess-a", call: "toolu_01A" })
  for (const bad of [
    "",
    "not json",
    "[1]",
    "null",
    JSON.stringify({ session_id: "sess-a" }),
    JSON.stringify({ tool_use_id: "toolu_01A" }),
    hookInput("sess a", "toolu_01A"),
    hookInput("sess-a", "toolu 01A"),
    hookInput("sess-a", 7),
    hookInput("x".repeat(129), "toolu_01A"),
  ]) {
    assert.equal(identity(bad), null, bad)
  }
})

test("interpret accepts only an exact v1 success", () => {
  assert.deepEqual(interpret(200, '{"version":1,"registered":true,"reason":"ok"}'), { registered: true, reason: "ok" })
  const refused = [
    [500, '{"version":1,"registered":true,"reason":"ok"}'],
    [200, '{"version":2,"registered":true,"reason":"ok"}'],
    [200, '{"version":1,"registered":"yes","reason":"ok"}'],
    [200, '{"version":1,"registered":true}'],
    [200, '{"version":1,"registered":true,"reason":"ok","extra":1}'],
    [200, '{"version":1,"registered":false,"reason":"capacity-exceeded"}'],
    [200, "ok"],
    [200, ""],
  ] as const
  for (const [status, body] of refused) {
    assert.equal(interpret(status, body).registered, false, `${status} ${body}`)
  }
})

test("register sends one versioned, content-free request", async (t) => {
  const m = await fakeMonitor(t, ok)
  const r = await register(m.socketPath, { session: "sess-a", call: "toolu_01A" })
  assert.deepEqual(r, { registered: true, reason: "ok" })
  assert.deepEqual(m.requests, [`POST ${PATH_REGISTER} {"version":${VERSION},"session":"sess-a","call":"toolu_01A"}`])
})

test("register reports failure for refused, malformed, stalled and absent monitors", async (t) => {
  const id = { session: "sess-a", call: "toolu_01A" }
  const refusing = await fakeMonitor(t, (_req, _body, res) => {
    res.writeHead(400)
    res.end('{"version":1,"registered":false,"reason":"malformed-request"}')
  })
  assert.deepEqual(await register(refusing.socketPath, id), { registered: false, reason: "malformed-request" })

  const garbled = await fakeMonitor(t, (_req, _body, res) => res.end("<html>"))
  assert.deepEqual(await register(garbled.socketPath, id), { registered: false, reason: "malformed-response" })

  const huge = await fakeMonitor(t, (_req, _body, res) => res.end("x".repeat(1 << 20)))
  assert.deepEqual(await register(huge.socketPath, id), { registered: false, reason: "malformed-response" })

  const stalled = await fakeMonitor(t, () => {})
  const start = Date.now()
  assert.deepEqual(await register(stalled.socketPath, id, 100), { registered: false, reason: "monitor-unavailable" })
  assert.ok(Date.now() - start < 1000, "register outlived its timeout")

  assert.deepEqual(await register("/nonexistent/barmkin.sock", id), { registered: false, reason: "monitor-unavailable" })
})

test("readInput gives up on a stalled stdin", async () => {
  const stalled = new PassThrough()
  stalled.write('{"session_id":')
  assert.equal(await readInput(stalled, 50), null)
  const done = new PassThrough()
  done.end(hookInput("sess-a", "toolu_01A"))
  assert.equal(await readInput(done, 1000), hookInput("sess-a", "toolu_01A"))
})

test("shim process registers the call and stays silent", async (t) => {
  const m = await fakeMonitor(t, ok)
  const r = await runShim(hookInput("sess-a", "toolu_01A"), { BARMKIN_MONITOR_SOCKET: m.socketPath })
  assert.deepEqual(r, { code: 0, stdout: "", stderr: "" })
  assert.equal(m.requests.length, 1)
  assert.ok(!m.requests[0].includes("secret-content"), "tool input reached the monitor")
})

test("shim process exits 0 without registering when it cannot", async (t) => {
  const m = await fakeMonitor(t, ok)
  const cases = [
    { input: hookInput("sess-a", "toolu_01A"), env: {} },
    { input: "not json", env: { BARMKIN_MONITOR_SOCKET: m.socketPath } },
    { input: hookInput("sess-a", "toolu_01A"), env: { BARMKIN_MONITOR_SOCKET: "/nonexistent/barmkin.sock" } },
  ]
  for (const c of cases) {
    const r = await runShim(c.input, c.env)
    assert.equal(r.code, 0)
    assert.equal(r.stdout, "")
    assert.match(r.stderr, /\[barmkin-shim\] call not registered/)
  }
  assert.deepEqual(m.requests, [])
})
