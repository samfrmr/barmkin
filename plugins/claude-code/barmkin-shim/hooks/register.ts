// Barmkin shim for Claude Code, as a hooks module.
//
// Registers every tool call with the local barmkin monitor (POST
// /v1/register) before the managed `barmkin gate` PreToolUse hook asks
// whether it was registered. The gate allows only registered calls, so a
// session without this plugin can run no tools.
//
// Claude Code 2.1.x runs the managed PreToolUse hook before any plugin
// hook, and a managed deny is final, so a plugin PreToolUse hook would run
// too late. The shim registers instead from `session.append`, which sees
// each of the model's tool_use blocks, with the tool_use_id the gate will
// receive, before the tool call starts. Being a hooks module is also what
// lets managed settings seat it under `allowManagedHooksOnly` through
// `prependPlugins`.
//
// The request is versioned and content-free: only the session id and the
// tool_use_id are sent, never the tool name or input.
//
// The shim never decides anything and never holds up the conversation: a
// call it cannot register is left for the gate to deny.
//
// Environment variables:
//   BARMKIN_MONITOR_SOCKET   monitor Unix socket path (required)

import type { Register } from "claude-code"

export const VERSION = 1
export const PATH_REGISTER = "/v1/register"

// Each registration gives up after this long, well inside the gate's wait
// for it. $.http.fetch has no timeout of its own.
export const REQUEST_TIMEOUT_MS = 1000

// Same opaque token shape the monitor accepts for sessions and calls.
const TOKEN = /^[A-Za-z0-9._-]{1,128}$/

export interface Registration {
  registered: boolean
  reason: string
}

// toolUseIds lists the tool_use ids in a conversation row's blocks.
export function toolUseIds(content: readonly { type: string; [field: string]: unknown }[]): string[] {
  return content.filter((b) => b.type === "tool_use").map((b) => (typeof b.id === "string" ? b.id : ""))
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

export const register: Register = (on) => {
  on("session.append", async ($, e, next) => {
    if (e.message.type !== "assistant") return next(e)
    const calls = toolUseIds(e.message.content)
    if (calls.length === 0) return next(e)

    const socketPath = await $.env.get("BARMKIN_MONITOR_SOCKET")
    const session = await $.session.id()
    const one = async (call: string): Promise<Registration> => {
      if (!socketPath) return { registered: false, reason: "BARMKIN_MONITOR_SOCKET is not set" }
      if (!TOKEN.test(session) || !TOKEN.test(call)) {
        return { registered: false, reason: "no well-formed session id and tool_use_id" }
      }
      const sent = $.http
        .fetch(`http://barmkin${PATH_REGISTER}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ version: VERSION, session, call }),
          socketPath,
        })
        .then(
          (res) => interpret(res.status, res.text),
          () => ({ registered: false, reason: "monitor-unavailable" }),
        )
      const late = $.clock.sleep(REQUEST_TIMEOUT_MS).then(() => ({ registered: false, reason: "monitor-unavailable" }))
      return Promise.race([sent, late])
    }

    const results = await Promise.all(calls.map(one))
    results.forEach((r, i) => {
      if (!r.registered) {
        $.ui.log(`[barmkin-shim] call ${calls[i] || "(no id)"} not registered (${r.reason}); the barmkin gate will deny it`)
      }
    })
    return next(e)
  }).catch(($, e, next) => next(e))
}
