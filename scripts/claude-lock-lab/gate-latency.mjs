// Times the managed gate as a host spawns it, for scripts/claude-lock-lab.sh.
//
// usage: node gate-latency.mjs <barmkin> <socket> <n> <max-p50-ms>
//
// Registers one session with the monitor on <socket> as the shim does, then
// <n> times pre-registers a call and spawns `<barmkin> gate -socket <socket>`
// with that call's PreToolUse input, timing each process from spawn to exit.
// Every gate must allow. Prints p50, p95 and max, and exits 1 if p50 is not
// under <max-p50-ms>.
import { spawnSync } from "node:child_process"
import { request } from "node:http"

const [bin, socket, n, maxP50] = [process.argv[2], process.argv[3], Number(process.argv[4]), Number(process.argv[5])]

function post(op, body) {
  return new Promise((resolve, reject) => {
    const req = request({ socketPath: socket, path: `/v1/${op}`, method: "POST", headers: { "content-type": "application/json" } }, (res) => {
      res.resume()
      res.on("end", () => (res.statusCode === 200 ? resolve() : reject(new Error(`${op}: HTTP ${res.statusCode}`))))
    })
    req.on("error", reject)
    req.end(JSON.stringify({ version: 1, host: "claude_code", ...body }))
  })
}

const session = `latency-${process.pid}`
await post("register", { session, root: session, fresh: true, posture: { sandbox_enabled: true, allow_all_unix_sockets: false } })
const times = []
for (let i = 0; i < n; i++) {
  const call = `toolu_latency${i}`
  await post("preregister", { session, call })
  const input = JSON.stringify({ session_id: session, tool_use_id: call, hook_event_name: "PreToolUse", tool_name: "Bash", tool_input: { command: "true" } })
  const start = process.hrtime.bigint()
  const r = spawnSync(bin, ["gate", "-socket", socket], { input })
  times.push(Number(process.hrtime.bigint() - start) / 1e6)
  if (r.status !== 0) {
    console.error(`FAIL: gate run ${i} exited ${r.status}: ${r.stderr}`)
    process.exit(1)
  }
}
times.sort((a, b) => a - b)
const at = (q) => times[Math.min(times.length - 1, Math.floor(q * times.length))].toFixed(2)
console.log(`    gate process, spawn to exit: n=${n} p50=${at(0.5)}ms p95=${at(0.95)}ms max=${times.at(-1).toFixed(2)}ms`)
if (!(Number(at(0.5)) < maxP50)) {
  console.error(`FAIL: gate p50 ${at(0.5)}ms is not under ${maxP50}ms`)
  process.exit(1)
}
