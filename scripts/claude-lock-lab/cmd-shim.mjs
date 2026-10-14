// Lab probe: the shim as a plugin PreToolUse command hook, the shape the
// demo first shipped. It registers the hook input's session_id and
// tool_use_id with the monitor. The lab shows Claude Code 2.1.x never runs
// it before the managed gate, so the gate denies every call.
import { request } from "node:http"

let raw = ""
process.stdin.on("data", (c) => (raw += c)).on("end", () => {
  const { session_id: session, tool_use_id: call } = JSON.parse(raw)
  const body = JSON.stringify({ version: 1, session, call })
  const req = request({ socketPath: process.env.BARMKIN_MONITOR_SOCKET, path: "/v1/register", method: "POST" }, (res) => res.resume())
  req.on("error", () => {})
  req.end(body)
})
