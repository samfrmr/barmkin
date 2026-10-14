// Scripted Anthropic Messages API stand-in for scripts/claude-lock-lab.sh.
//
// usage: node mock-model.mjs <port-file> <scripts-dir> <log-file>
//
// Listens on a free 127.0.0.1 port and writes it to <port-file>. A prompt
// carrying "SCRIPT:<name>" gets, on its first turn, one Bash call per line
// of <scripts-dir>/<name>.cmd (default: `echo ORIGINAL > markers/<name>.txt`),
// or one Agent call whose prompt is "SCRIPT:<name>-sub" when
// <scripts-dir>/<name>.agent exists. A line "READ <path>" is a Read call
// instead, a line "FETCH <url>" a WebFetch call, and a line "---" ends one turn's calls: each later turn makes the
// next group's calls. Once every group has run it ends the turn quoting the
// tool results. Each request is logged as a JSON line. Nothing here reaches
// the network.
import { createServer } from "node:http"
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs"

const [portFile, scripts, logFile] = process.argv.slice(2)
let seq = 0

function text(content) {
  if (typeof content === "string") return content
  if (!Array.isArray(content)) return ""
  return content.map((b) => (b.type === "text" ? b.text : "")).join("\n")
}

function plan(body) {
  const msgs = body.messages ?? []
  const m = msgs.map((x) => text(x.content)).join("\n").match(/SCRIPT:([A-Za-z0-9_-]+)/)
  const tools = body.tools ?? []
  if (!m || !tools.some((t) => t.name === "Bash")) return { text: "ok" }
  const name = m[1]
  const f = `${scripts}/${name}.cmd`
  const groups = (existsSync(f) ? readFileSync(f, "utf8") : `echo ORIGINAL > markers/${name}.txt`).split(/^---$/m)
  const turn = msgs.filter((x) => x.role === "assistant" && Array.isArray(x.content) && x.content.some((b) => b.type === "tool_use")).length
  const results = msgs.flatMap((x) => (Array.isArray(x.content) ? x.content : [])).filter((b) => b.type === "tool_result")
  if (results.length > 0 && turn >= groups.length) {
    return { text: results.map((r) => `RESULT is_error=${!!r.is_error} ${JSON.stringify(r.content).slice(0, 400)}`).join(" || ") }
  }
  const id = () => `toolu_lab${String(++seq).padStart(4, "0")}`
  const agent = tools.find((t) => t.name === "Agent" || t.name === "Task")
  if (turn === 0 && agent && existsSync(`${scripts}/${name}.agent`)) {
    return {
      uses: [{ id: id(), name: agent.name, input: { description: "lab subagent", prompt: `SCRIPT:${name}-sub go`, subagent_type: "general-purpose" } }],
    }
  }
  const lines = groups[Math.min(turn, groups.length - 1)].split("\n").filter(Boolean)
  return {
    uses: lines.map((line) =>
      line.startsWith("READ ")
        ? { id: id(), name: "Read", input: { file_path: line.slice(5) } }
        : line.startsWith("FETCH ")
          ? { id: id(), name: "WebFetch", input: { url: line.slice(6), prompt: "lab probe" } }
          : { id: id(), name: "Bash", input: { command: line, description: "lab probe" } },
    ),
  }
}

function stream(res, model, p) {
  res.writeHead(200, { "content-type": "text/event-stream" })
  const send = (type, data) => res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...data })}\n\n`)
  send("message_start", {
    message: { id: `msg_lab${seq}`, type: "message", role: "assistant", model, content: [], stop_reason: null, usage: { input_tokens: 10, output_tokens: 1 } },
  })
  const blocks = p.uses ?? [{ text: p.text }]
  blocks.forEach((b, index) => {
    if (b.text !== undefined) {
      send("content_block_start", { index, content_block: { type: "text", text: "" } })
      send("content_block_delta", { index, delta: { type: "text_delta", text: b.text } })
    } else {
      send("content_block_start", { index, content_block: { type: "tool_use", id: b.id, name: b.name, input: {} } })
      send("content_block_delta", { index, delta: { type: "input_json_delta", partial_json: JSON.stringify(b.input) } })
    }
    send("content_block_stop", { index })
  })
  send("message_delta", { delta: { stop_reason: p.uses ? "tool_use" : "end_turn", stop_sequence: null }, usage: { output_tokens: 5 } })
  send("message_stop", {})
  res.end()
}

const server = createServer((req, res) => {
  let raw = ""
  req.on("data", (c) => (raw += c))
  req.on("end", () => {
    let body = {}
    try {
      body = JSON.parse(raw || "{}")
    } catch {}
    const json = (status, v) => {
      res.writeHead(status, { "content-type": "application/json" })
      res.end(JSON.stringify(v))
    }
    if (req.url.includes("count_tokens")) return json(200, { input_tokens: 10 })
    if (!req.url.startsWith("/v1/messages")) {
      appendFileSync(logFile, JSON.stringify({ t: Date.now(), method: req.method, url: req.url }) + "\n")
      return json(404, { type: "error", error: { type: "not_found_error", message: "lab mock" } })
    }
    const p = plan(body)
    appendFileSync(logFile, JSON.stringify({ t: Date.now(), url: req.url, plan: p }) + "\n")
    const model = body.model ?? "claude-lab"
    if (body.stream) return stream(res, model, p)
    const content = p.uses ? p.uses.map((u) => ({ type: "tool_use", ...u })) : [{ type: "text", text: p.text }]
    json(200, {
      id: `msg_lab${seq}`, type: "message", role: "assistant", model, content,
      stop_reason: p.uses ? "tool_use" : "end_turn", stop_sequence: null, usage: { input_tokens: 10, output_tokens: 5 },
    })
  })
})
server.listen(0, "127.0.0.1", () => writeFileSync(portFile, String(server.address().port)))
