// Contract tests: the shim's monitor client code (barmkin-shim/hooks/lib)
// against a real `barmkin monitor`. Run by `go test` (TestShimMonitorContract
// in gate_test.go), which starts the monitor and passes its socket in
// BARMKIN_TEST_MONITOR_SOCKET. Run alone with:
//   BARMKIN_TEST_MONITOR_SOCKET=/path/to/monitor.sock node --test monitor-contract.test.ts
//
// Inside Claude Code the shim posts through $.http.fetch with socketPath;
// here node:http does the same over the same socket, and every reply goes
// through the shim's own interpretReply.

import { test } from "node:test"
import assert from "node:assert/strict"
import { request } from "node:http"
import { encodeBody, interpretReply, monitorUrl, type Answer } from "./barmkin-shim/hooks/lib/monitor.ts"
import { CLASSES, VERSION, type Class, type Legs, type Op, type Requests } from "./barmkin-shim/hooks/lib/proto.ts"
import { decideLike } from "./barmkin-shim/tests/support/fake-monitor.ts"

const socketPath = process.env.BARMKIN_TEST_MONITOR_SOCKET ?? ""
const skip = socketPath === "" ? "BARMKIN_TEST_MONITOR_SOCKET is not set" : false

function postRaw(op: Op, body: string): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = request(
      monitorUrl(op),
      { method: "POST", socketPath, headers: { "content-type": "application/json" }, timeout: 2000 },
      (res) => {
        let text = ""
        res.setEncoding("utf8")
        res.on("data", (c) => (text += c))
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text }))
      },
    )
    req.on("error", reject)
    req.end(body)
  })
}

async function send<O extends Op>(op: O, req: Requests[O]): Promise<Answer<O>> {
  const body = encodeBody(op, req)
  assert.notEqual(body, null, `the shim refuses to encode ${op}`)
  const res = await postRaw(op, body!)
  return interpretReply(op, res.status, res.text)
}

function ok<O extends Op>(answer: Answer<O>) {
  if (!answer.ok) assert.fail(`monitor answered ${answer.failure}`)
  return answer.value
}

let n = 0
const token = (what: string) => `${what}-${process.pid}-${++n}`
const host = "claude_code" as const
const SANDBOXED = { sandbox_enabled: true, allow_all_unix_sockets: false }

async function fresh(session = token("s")): Promise<string> {
  ok(await send("register", { version: VERSION, host, session, root: session, fresh: true, posture: SANDBOXED }))
  return session
}

const scoped = (session: string) => ({ version: VERSION, host, session })

test("a fresh session registers clean, and registering again changes nothing", { skip }, async () => {
  const session = await fresh()
  const again = ok(await send("register", { ...scoped(session), root: session, fresh: true, posture: SANDBOXED }))
  assert.deepEqual(again.legs, { untrusted: "none", sensitive: "none" })
})

test("a session the monitor has never seen that is not fresh starts tainted", { skip }, async () => {
  const session = token("resumed")
  const reg = ok(await send("register", { ...scoped(session), root: session, fresh: false, posture: SANDBOXED }))
  assert.deepEqual(reg.legs, { untrusted: "unknown_session", sensitive: "none" })
})

test("an unsandboxed posture, or one that opens every Unix socket, is refused", { skip }, async () => {
  for (const posture of [{ sandbox_enabled: false, allow_all_unix_sockets: false }, { sandbox_enabled: true, allow_all_unix_sockets: true }]) {
    const session = token("posture")
    const answer = await send("register", { ...scoped(session), root: session, fresh: true, posture })
    assert.deepEqual(answer, { ok: false, failure: "posture_refused" })
    assert.deepEqual(await send("status", scoped(session)), { ok: false, failure: "unknown_session" })
  }
})

test("a request about a session never registered fails unknown_session", { skip }, async () => {
  assert.deepEqual(await send("decide", { ...scoped(token("ghost")), classes: [] }), { ok: false, failure: "unknown_session" })
  assert.deepEqual(await send("preregister", { ...scoped(token("ghost")), call: "toolu_x" }), { ok: false, failure: "unknown_session" })
})

test("a pre-registered call admits one gate check", { skip }, async () => {
  const session = await fresh()
  const pre = ok(await send("preregister", { ...scoped(session), call: "toolu_01" }))
  assert.ok(pre.ttl_ms > 0)
  assert.equal(ok(await send("gate", { ...scoped(session), call: "toolu_01" })).preregistered, true)
  assert.equal(ok(await send("gate", { ...scoped(session), call: "toolu_01" })).preregistered, false)
  assert.equal(ok(await send("gate", { ...scoped(session), call: "toolu_02" })).preregistered, false)
})

test("observe raises legs, the first source stays, and nothing lowers them", { skip }, async () => {
  const session = await fresh()
  assert.deepEqual(ok(await send("observe", { ...scoped(session), source: "fetch" })).legs, { untrusted: "fetch", sensitive: "none" })
  assert.deepEqual(ok(await send("observe", { ...scoped(session), source: "mcp" })).legs, { untrusted: "fetch", sensitive: "none" })
  assert.deepEqual(ok(await send("observe", { ...scoped(session), source: "credential" })).legs, { untrusted: "fetch", sensitive: "credential" })
  const again = ok(await send("register", { ...scoped(session), root: session, fresh: true, posture: SANDBOXED }))
  assert.deepEqual(again.legs, { untrusted: "fetch", sensitive: "credential" })
})

test("a new session id in the same process (after /clear) joins its root's lineage", { skip }, async () => {
  const root = await fresh()
  ok(await send("observe", { ...scoped(root), source: "skill" }))
  const next = token("after-clear")
  const reg = ok(await send("register", { ...scoped(next), root, fresh: false, posture: SANDBOXED }))
  assert.deepEqual(reg.legs, { untrusted: "skill", sensitive: "none" })

  const cleanRoot = await fresh()
  const cleanNext = token("after-clear")
  const clean = ok(await send("register", { ...scoped(cleanNext), root: cleanRoot, fresh: false, posture: SANDBOXED }))
  assert.deepEqual(clean.legs, { untrusted: "none", sensitive: "none" })
})

test("decide matches the shim tests' monitor (decideLike) for every class in every leg state", { skip }, async () => {
  const states: { name: string; raise: ("fetch" | "credential")[] }[] = [
    { name: "clean", raise: [] },
    { name: "untrusted", raise: ["fetch"] },
    { name: "sensitive only", raise: ["credential"] },
    { name: "both", raise: ["fetch", "credential"] },
  ]
  for (const state of states) {
    const session = await fresh()
    let legs: Legs = { untrusted: "none", sensitive: "none" }
    for (const source of state.raise) legs = ok(await send("observe", { ...scoped(session), source })).legs
    const sets: Class[][] = [[], ...CLASSES.map((c) => [c]), [...CLASSES], ["destructive", "web-search"], ["web-fetch", "persistence"]]
    for (const classes of sets) {
      const real = ok(await send("decide", { ...scoped(session), classes }))
      assert.deepEqual(
        { verdict: real.verdict, rule: real.rule, classes: real.classes },
        decideLike(classes, legs),
        `${state.name}: ${classes.join(",") || "(no classes)"}`,
      )
      assert.deepEqual(real.legs, legs)
    }
  }
})

test("the monitor core has no screen yet: screen raises the leg and answers unavailable", { skip }, async () => {
  const session = await fresh()
  const answer = await send("screen", {
    ...scoped(session),
    source: "fetch",
    windows: ["[REDACTED:api-key#1] an ordinary page"],
    scores: { injection: 0, credentials: 0.9, exfiltration: 0 },
  })
  assert.deepEqual(answer, { ok: false, failure: "unavailable" })
  const status = ok(await send("status", scoped(session)))
  assert.deepEqual(status.legs, { untrusted: "fetch", sensitive: "none" })
  assert.equal(status.classifier, "degraded")
})

test("a request from another contract version is a version mismatch the shim reads as such", { skip }, async () => {
  const session = await fresh()
  const res = await postRaw("decide", JSON.stringify({ version: VERSION + 1, host, session, classes: [] }))
  assert.deepEqual(interpretReply("decide", res.status, res.text), { ok: false, failure: "version_mismatch" })
})

test("a malformed request is refused as bad_request", { skip }, async () => {
  const res = await postRaw("decide", JSON.stringify({ version: VERSION, host, session: "s", classes: ["exfil"] }))
  assert.deepEqual(interpretReply("decide", res.status, res.text), { ok: false, failure: "bad_request" })
})

test("health answers without a session", { skip }, async () => {
  assert.deepEqual(ok(await send("health", { version: VERSION })), { version: VERSION, state: "ok" })
})
