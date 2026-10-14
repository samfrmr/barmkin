// Lab probe: the shim as a plugin PreToolUse command hook, the shape the
// demo first shipped. It registers the hook input's session_id and
// pre-registers its tool_use_id with the monitor, as the real shim does.
// The lab shows Claude Code 2.1.x never runs it before the managed gate, so
// the gate denies every call.
import { request } from "node:http"

function post(op, body) {
  return new Promise((resolve) => {
    const req = request({ socketPath: process.env.BARMKIN_MONITOR_SOCKET, path: `/v1/${op}`, method: "POST" }, (res) => res.resume().on("end", resolve))
    req.on("error", resolve)
    req.end(JSON.stringify(body))
  })
}

let raw = ""
process.stdin.on("data", (c) => (raw += c)).on("end", async () => {
  const { session_id: session, tool_use_id: call } = JSON.parse(raw)
  const host = "claude_code"
  await post("register", { version: 1, host, session, root: session, fresh: true, posture: { sandbox_enabled: true, allow_all_unix_sockets: false } })
  await post("preregister", { version: 1, host, session, call })
})
