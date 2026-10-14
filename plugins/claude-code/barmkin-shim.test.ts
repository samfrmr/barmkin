// Tests for the barmkin shim's hooks module. Run with:
//   node --test barmkin-shim.test.ts
//
// The module runs inside Claude Code with the engine's `$`. Here it runs
// against a stand-in `$` with the same calls, so each test controls the
// environment, the session id, the clock and the monitor's answers, and
// sees what the shim sends and when the row reaches the store (`next`).
// The live lab (scripts/claude-lock-lab.sh) runs it inside Claude Code.

import { test } from "node:test"
import assert from "node:assert/strict"
import { interpret, PATH_REGISTER, register, REQUEST_TIMEOUT_MS, toolUseIds, VERSION } from "./barmkin-shim/hooks/register.ts"

const SOCKET = "/run/barmkin/monitor.sock"
const OK = JSON.stringify({ version: VERSION, registered: true, reason: "registered" })

type Reply = () => Promise<{ status: number; text: string }>
type Hook = ($: unknown, e: unknown, next: (e: unknown) => Promise<unknown>) => Promise<unknown>
interface Sent {
  url: string
  method?: string
  socketPath?: string
  body?: string
}

// load runs the module's register and returns the session.append hook
// with its .catch handler.
function load(): { hook: Hook; fallback: Hook } {
  let hook: Hook | undefined
  let fallback: Hook | undefined
  const on = (event: string, h: Hook) => {
    assert.equal(event, "session.append")
    hook = h
    return { catch: (f: Hook) => void (fallback = f) }
  }
  ;(register as unknown as (on: unknown) => void)(on)
  assert.ok(hook && fallback, "register adds a session.append hook with a .catch handler")
  return { hook, fallback }
}

// world is the stand-in for Claude Code beneath the shim. events records
// the order of registrations and the row's store.
function world(opts: { env?: Record<string, string>; session?: string; reply?: Reply } = {}) {
  const sent: Sent[] = []
  const logs: string[] = []
  const events: string[] = []
  const sleeps: (() => void)[] = []
  const env = opts.env ?? { BARMKIN_MONITOR_SOCKET: SOCKET }
  const reply = opts.reply ?? (async () => ({ status: 200, text: OK }))
  const $ = {
    env: { get: async (name: string) => env[name] },
    session: { id: async () => opts.session ?? "sess-a" },
    clock: { sleep: () => new Promise<void>((resolve) => sleeps.push(resolve)) },
    ui: { log: (text: string) => void logs.push(text) },
    http: {
      fetch: async (url: string, init: { method?: string; socketPath?: string; body?: string }) => {
        sent.push({ url, method: init.method, socketPath: init.socketPath, body: init.body })
        events.push("register")
        const r = await reply()
        return { status: r.status, ok: r.status >= 200 && r.status < 300, headers: {}, text: r.text }
      },
    },
  }
  const next = async (e: unknown) => {
    events.push("stored")
    return e
  }
  // expire fires every pending $.clock.sleep, as the deadline passing.
  const expire = () => sleeps.splice(0).forEach((f) => f())
  return { $, next, sent, logs, events, expire }
}

function row(type: string, ...ids: string[]) {
  return {
    message: {
      type,
      content: [
        { type: "text", text: "running it" },
        ...ids.map((id) => ({ type: "tool_use", id, name: "Bash", input: { command: "echo secret-content" } })),
      ],
    },
    door: type === "assistant" ? "response" : "prompt",
    uuid: "row-1",
  }
}

test("registers every tool call in a response before the row is stored", async () => {
  const w = world()
  const e = row("assistant", "toolu_01", "toolu_02")
  assert.equal(await load().hook(w.$, e, w.next), e)
  assert.deepEqual(w.events, ["register", "register", "stored"])
  assert.deepEqual(
    w.sent.map((s) => JSON.parse(s.body ?? "null")),
    [
      { version: 1, session: "sess-a", call: "toolu_01" },
      { version: 1, session: "sess-a", call: "toolu_02" },
    ],
  )
  for (const s of w.sent) {
    assert.equal(s.url, `http://barmkin${PATH_REGISTER}`)
    assert.equal(s.method, "POST")
    assert.equal(s.socketPath, SOCKET)
  }
  assert.deepEqual(w.logs, [])
})

test("sends no tool name, input or text", async () => {
  const w = world()
  await load().hook(w.$, row("assistant", "toolu_01"), w.next)
  assert.equal(w.sent.length, 1)
  assert.doesNotMatch(w.sent[0]!.body!, /Bash|secret-content|running it/)
})

test("leaves rows without tool calls alone", async () => {
  const w = world()
  const { hook } = load()
  await hook(w.$, row("assistant"), w.next)
  await hook(w.$, row("user", "toolu_01"), w.next)
  assert.deepEqual(w.sent, [])
  assert.deepEqual(w.events, ["stored", "stored"])
})

test("does not register without a monitor socket, and keeps the row", async () => {
  const w = world({ env: {} })
  await load().hook(w.$, row("assistant", "toolu_01"), w.next)
  assert.deepEqual(w.sent, [])
  assert.deepEqual(w.events, ["stored"])
  assert.match(w.logs[0]!, /toolu_01 not registered \(BARMKIN_MONITOR_SOCKET is not set\)/)
})

test("does not register malformed session or call ids", async () => {
  for (const [session, call] of [
    ["sess a", "toolu_01"],
    ["sess-a", "toolu 01"],
    ["sess-a", ""],
    ["sess-a", "x".repeat(129)],
  ]) {
    const w = world({ session })
    await load().hook(w.$, row("assistant", call!), w.next)
    assert.deepEqual(w.sent, [], `${session}/${call}`)
    assert.deepEqual(w.events, ["stored"])
    assert.match(w.logs[0]!, /not registered \(no well-formed session id and tool_use_id\)/)
  }
})

test("treats anything but a 200 v1 success as not registered", async () => {
  const replies = [
    { status: 200, text: JSON.stringify({ version: 1, registered: false, reason: "capacity" }) },
    { status: 500, text: OK },
    { status: 200, text: "not json" },
    { status: 200, text: JSON.stringify({ version: 2, registered: true, reason: "registered" }) },
    { status: 200, text: JSON.stringify({ version: 1, registered: true, reason: "registered", extra: 1 }) },
  ]
  for (const [i, r] of replies.entries()) {
    const w = world({ reply: async () => r })
    await load().hook(w.$, row("assistant", "toolu_01"), w.next)
    assert.equal(w.logs.length, 1, `reply ${i}`)
    assert.deepEqual(w.events, ["register", "stored"])
  }
  assert.deepEqual(interpret(200, OK), { registered: true, reason: "registered" })
  assert.deepEqual(interpret(500, OK), { registered: false, reason: "registered" })
  assert.deepEqual(interpret(200, "[]"), { registered: false, reason: "malformed-response" })
})

test("gives up on a monitor that does not answer, and keeps the row", async () => {
  const w = world({ reply: () => new Promise(() => {}) })
  const done = load().hook(w.$, row("assistant", "toolu_01"), w.next)
  await new Promise((r) => setImmediate(r))
  assert.deepEqual(w.events, ["register"])
  w.expire()
  await done
  assert.deepEqual(w.events, ["register", "stored"])
  assert.match(w.logs[0]!, /toolu_01 not registered \(monitor-unavailable\)/)
  assert.ok(REQUEST_TIMEOUT_MS <= 1000, "registration gives up well inside the gate's 1.5s wait")
})

test("keeps the row when the fetch fails", async () => {
  const w = world({ reply: () => Promise.reject(new Error("ENOENT")) })
  await load().hook(w.$, row("assistant", "toolu_01"), w.next)
  assert.deepEqual(w.events, ["register", "stored"])
  assert.match(w.logs[0]!, /toolu_01 not registered \(monitor-unavailable\)/)
})

test("the .catch handler keeps the row", async () => {
  const w = world()
  const e = row("assistant", "toolu_01")
  assert.equal(await load().fallback(w.$, e, w.next), e)
  assert.deepEqual(w.events, ["stored"])
})

test("toolUseIds lists tool_use blocks only", () => {
  assert.deepEqual(
    toolUseIds([
      { type: "text", text: "a" },
      { type: "tool_use", id: "toolu_01" },
      { type: "tool_result", tool_use_id: "toolu_00" },
      { type: "tool_use", id: 7 },
    ]),
    ["toolu_01", ""],
  )
})
