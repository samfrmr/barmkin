// A broken stand-in for `barmkin monitor` on its socket, for
// scripts/claude-lock-lab.sh.
//
// usage: node fake-monitor.mjs <socket> stall|version
//
//   stall    accepts every connection and never answers
//   version  answers every request as a monitor of contract version 2
import { createServer } from "node:net"
import { rmSync } from "node:fs"

const [socket, mode] = process.argv.slice(2)
const body = JSON.stringify({ version: 2, error: "version_mismatch" })
const server = createServer((conn) => {
  conn.on("error", () => {})
  if (mode === "stall") return
  conn.once("data", () =>
    conn.end(`HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`),
  )
})
rmSync(socket, { force: true })
server.listen(socket)
