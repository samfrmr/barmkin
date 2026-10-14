// Fixture tests for the wire contract. Run with:
//   node --test proto.test.ts
//
// The fixtures are the Go package's (internal/proto/testdata), so both
// sides agree on every message. Each <op>.json holds valid messages, which
// must decode and re-encode to the same bytes, and invalid ones, which
// must fail with the given code. transport.json pins the shared constants
// and paths.

import { test } from "node:test"
import assert from "node:assert/strict"
import { readdirSync, readFileSync } from "node:fs"
import { join } from "node:path"
import {
  CLIENT_DEADLINE_MS,
  CODES,
  decodeError,
  decodeRequest,
  decodeResponse,
  encodeError,
  encodeRequest,
  encodeResponse,
  HTTP_STATUS,
  MAX_BODY_BYTES,
  type Op,
  opPath,
  OPS,
  parsePath,
  PATH_PREFIX,
  ProtoError,
  VERSION,
} from "./proto.ts"

const TESTDATA = join(import.meta.dirname, "..", "..", "internal", "proto", "testdata")

interface FixtureCase {
  name: string
  message: "request" | "response" | "error"
  body?: unknown
  raw?: string
  error?: string
}

interface FixtureFile {
  op: Op
  valid: FixtureCase[]
  invalid: FixtureCase[]
}

const read = (file: string): unknown => JSON.parse(readFileSync(join(TESTDATA, file), "utf8"))

// roundTrip decodes raw as the case's message and encodes it again.
function roundTrip(op: Op, message: FixtureCase["message"], raw: string): string {
  switch (message) {
    case "request":
      return encodeRequest(op, decodeRequest(op, raw))
    case "response":
      return encodeResponse(op, decodeResponse(op, raw))
    case "error":
      return encodeError(decodeError(raw))
  }
}

test("transport constants and paths match the fixtures", () => {
  const t = read("transport.json") as Record<string, unknown>
  assert.equal(t.version, VERSION)
  assert.equal(t.path_prefix, PATH_PREFIX)
  assert.equal(t.max_body_bytes, MAX_BODY_BYTES)
  assert.equal(t.client_deadline_ms, CLIENT_DEADLINE_MS)
  assert.deepEqual(t.ops, OPS)
  for (const op of OPS) assert.equal(parsePath(opPath(op)), op)
  for (const p of t.unknown_paths as string[]) assert.equal(parsePath(p), undefined, p)
  assert.deepEqual(t.codes, HTTP_STATUS)
  assert.deepEqual(Object.keys(HTTP_STATUS), [...CODES])
})

const files = readdirSync(TESTDATA)
  .filter((f) => f.endsWith(".json") && f !== "transport.json")
  .sort()

test("fixture files cover every operation", () => {
  assert.deepEqual(files, [...OPS].sort().map((op) => `${op}.json`))
})

for (const file of files) {
  const f = read(file) as FixtureFile
  assert.equal(`${f.op}.json`, file)

  test(`${f.op}: has a valid request and response`, () => {
    const kinds = new Set(f.valid.map((c) => c.message))
    assert.ok(kinds.has("request") && kinds.has("response"))
  })

  for (const c of f.valid) {
    test(`${f.op}/valid/${c.name}`, () => {
      const raw = JSON.stringify(c.body)
      assert.equal(roundTrip(f.op, c.message, raw), raw)
    })
  }

  for (const c of f.invalid) {
    test(`${f.op}/invalid/${c.name}`, () => {
      const raw = c.raw ?? JSON.stringify(c.body)
      assert.throws(
        () => roundTrip(f.op, c.message, raw),
        (err: unknown) => err instanceof ProtoError && err.code === c.error,
      )
    })
  }
}
