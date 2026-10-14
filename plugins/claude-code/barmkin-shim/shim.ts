// Barmkin shim for Claude Code.
//
// Runs as this plugin's PreToolUse hook on every tool call and registers
// the call with the local barmkin monitor (POST /v1/register) before the
// managed `barmkin gate` hook asks whether it was registered. The gate
// allows only registered calls, so tool calls in a session without this
// plugin are denied.
//
// The request is versioned and content-free: only Claude Code's
// session_id and tool_use_id are sent, never the tool name or input.
//
// The shim always exits 0 and prints nothing on stdout. It never decides
// anything itself: if it cannot register a call, the gate denies it.
//
// Environment variables:
//   BARMKIN_MONITOR_SOCKET   monitor Unix socket path (required)

import { request } from "node:http"

export const VERSION = 1
export const PATH_REGISTER = "/v1/register"

// Bounds that keep the shim well inside the gate's wait for it.
export const STDIN_TIMEOUT_MS = 1000
export const REQUEST_TIMEOUT_MS = 1000
export const MAX_INPUT_BYTES = 64 << 20
const MAX_RESPONSE_BYTES = 4096

// Same opaque token shape the monitor accepts for sessions and calls.
const TOKEN = /^[A-Za-z0-9._-]{1,128}$/

export interface Identity {
  session: string
  call: string
}

export interface Registration {
  registered: boolean
  reason: string
}

// identity pulls the session and tool-call tokens out of the PreToolUse
// hook input. It returns null unless both are present and well-formed.
export function identity(raw: string): Identity | null {
  let input: unknown
  try {
    input = JSON.parse(raw)
  } catch {
    return null
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) return null
  const { session_id: session, tool_use_id: call } = input as Record<string, unknown>
  if (typeof session !== "string" || !TOKEN.test(session)) return null
  if (typeof call !== "string" || !TOKEN.test(call)) return null
  return { session, call }
}

// register sends one v1 registration over the monitor socket. It resolves
// to registered only for an HTTP 200 carrying exactly a v1 success.
export function register(socketPath: string, id: Identity, timeoutMs = REQUEST_TIMEOUT_MS): Promise<Registration> {
  const body = JSON.stringify({ version: VERSION, session: id.session, call: id.call })
  return new Promise((resolve) => {
    let settled = false
    const done = (r: Registration) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve(r)
    }
    const req = request(
      {
        socketPath,
        path: PATH_REGISTER,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) },
      },
      (res) => {
        const chunks: Buffer[] = []
        let size = 0
        res.on("data", (c: Buffer) => {
          size += c.length
          if (size > MAX_RESPONSE_BYTES) {
            req.destroy()
            done({ registered: false, reason: "malformed-response" })
            return
          }
          chunks.push(c)
        })
        res.on("end", () => done(interpret(res.statusCode ?? 0, Buffer.concat(chunks).toString("utf8"))))
        res.on("error", () => done({ registered: false, reason: "monitor-unavailable" }))
      },
    )
    const timer = setTimeout(() => {
      req.destroy()
      done({ registered: false, reason: "monitor-unavailable" })
    }, timeoutMs)
    req.on("error", () => done({ registered: false, reason: "monitor-unavailable" }))
    req.end(body)
  })
}

// interpret accepts only {"version":1,"registered":true,"reason":...} with
// HTTP 200 and no other keys.
export function interpret(status: number, raw: string): Registration {
  let resp: unknown
  try {
    resp = JSON.parse(raw)
  } catch {
    return { registered: false, reason: "malformed-response" }
  }
  if (!resp || typeof resp !== "object" || Array.isArray(resp)) {
    return { registered: false, reason: "malformed-response" }
  }
  const r = resp as Record<string, unknown>
  const keys = Object.keys(r).sort().join(",")
  if (keys !== "reason,registered,version" || r.version !== VERSION || typeof r.reason !== "string" || r.reason === "") {
    return { registered: false, reason: "malformed-response" }
  }
  return { registered: status === 200 && r.registered === true, reason: r.reason }
}

// readInput reads stdin up to the input bound, giving up after the
// stdin timeout. It resolves to null on any failure.
export function readInput(stream: NodeJS.ReadableStream, timeoutMs = STDIN_TIMEOUT_MS): Promise<string | null> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    let size = 0
    let settled = false
    const finish = (v: string | null) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      stream.removeAllListeners("data")
      resolve(v)
    }
    const timer = setTimeout(() => finish(null), timeoutMs)
    stream.on("data", (c: Buffer) => {
      size += c.length
      if (size > MAX_INPUT_BYTES) return finish(null)
      chunks.push(c)
    })
    stream.on("end", () => finish(Buffer.concat(chunks).toString("utf8")))
    stream.on("error", () => finish(null))
  })
}

async function main(): Promise<void> {
  const socketPath = process.env.BARMKIN_MONITOR_SOCKET
  const raw = await readInput(process.stdin)
  const id = raw === null ? null : identity(raw)
  let reason: string
  if (!socketPath) reason = "BARMKIN_MONITOR_SOCKET is not set"
  else if (!id) reason = "hook input has no well-formed session_id and tool_use_id"
  else {
    const r = await register(socketPath, id)
    if (r.registered) process.exit(0)
    reason = r.reason
  }
  process.stderr.write(`[barmkin-shim] call not registered (${reason}); the barmkin gate will deny it\n`)
  process.exit(0)
}

if (import.meta.main) {
  main().catch(() => process.exit(0))
}
