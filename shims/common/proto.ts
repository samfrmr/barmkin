// Barmkin shim/monitor wire contract: the TypeScript mirror of the Go
// package internal/proto, whose package doc is the reference. Both sides
// are tested against the same fixtures in internal/proto/testdata.
//
// Each operation is an HTTP POST of one JSON object to /v1/<op> on the
// monitor's Unix socket. A success is HTTP 200 with the operation's
// response; a failure is the status in HTTP_STATUS with an ErrorResponse.
//
// Taint is sticky: legs only rise, and there is no clear or rotate
// operation, no clear capability, and no human-prompt rotation.
//
// Every request and response carries `version`, which must equal VERSION.
// A shim that sees a version mismatch, an error code, a malformed reply or
// no reply within CLIENT_DEADLINE_MS denies the guarded call.

export const VERSION = 1
export const PATH_PREFIX = "/v1/"
export const MAX_BODY_BYTES = 128 * 1024
export const CLIENT_DEADLINE_MS = 1000

// Screen request bounds, in UTF-16 code units (String.prototype.length).
export const MAX_WINDOWS = 5
export const MAX_WINDOW_SIZE = 4000

export const OPS = ["register", "preregister", "gate", "decide", "screen", "observe", "status", "health"] as const
export type Op = (typeof OPS)[number]

export const CODES = ["bad_request", "version_mismatch", "unknown_session", "posture_refused", "unavailable"] as const
export type Code = (typeof CODES)[number]

// HTTP_STATUS is the status a monitor sends with an ErrorResponse.
export const HTTP_STATUS: Readonly<Record<Code, number>> = {
  bad_request: 400,
  version_mismatch: 400,
  unknown_session: 404,
  posture_refused: 403,
  unavailable: 503,
}

export const HOSTS = ["claude_code", "opencode"] as const
export type Host = (typeof HOSTS)[number]

// Untrusted (leg A) sources a shim reports.
export const UNTRUSTED_SHIM_SOURCES = ["mcp", "fetch", "read", "peer", "skill", "invisible"] as const
// Untrusted (leg A) sources only the monitor sets.
export const UNTRUSTED_MONITOR_SOURCES = ["unknown_session", "monitor_restart"] as const
export type Source =
  | "none"
  | (typeof UNTRUSTED_SHIM_SOURCES)[number]
  | (typeof UNTRUSTED_MONITOR_SOURCES)[number]
  | "credential" // the sensitive (leg B) source

export const CLASSES = [
  "shell-outward",
  "net-client",
  "dns",
  "forge",
  "publish",
  "cloud",
  "interpreter-net",
  "persist-shell",
  "destructive",
  "history-rewrite",
  "web-fetch",
  "web-search",
  "monitor-ws",
  "mcp-write",
  "skill-load",
  "persistence",
] as const
export type Class = (typeof CLASSES)[number]

export type Verdict = "pass" | "warn" | "deny"
export type Rule = "none" | "untrusted" | "rule_of_two"
export type ScreenDecision = "pass" | "escalate" | "deny"
export type Gap = "none" | "scan_limit" | "unclassified"
export type Health = "ok" | "degraded"
export type ClassifierState = "ok" | "degraded"

export interface Legs {
  untrusted: Source
  sensitive: Source
}

export interface Posture {
  sandbox_enabled: boolean
  allow_all_unix_sockets: boolean
}

export interface Scores {
  injection: number
  credentials: number
  exfiltration: number
}

interface Scoped {
  version: number
  host: Host
  session: string
}

export interface RegisterRequest extends Scoped {
  root: string
  fresh: boolean
  posture: Posture
}
export interface RegisterResponse {
  version: number
  legs: Legs
}
export interface PreregisterRequest extends Scoped {
  call: string
}
export interface PreregisterResponse {
  version: number
  ttl_ms: number
}
export interface GateRequest extends Scoped {
  call: string
}
export interface GateResponse {
  version: number
  preregistered: boolean
}
export interface DecideRequest extends Scoped {
  classes: Class[]
}
export interface DecideResponse {
  version: number
  verdict: Verdict
  rule: Rule
  classes: Class[]
  legs: Legs
}
export interface ScreenRequest extends Scoped {
  source: Source
  windows: string[]
  scores: Scores
}
export interface ScreenResponse {
  version: number
  decision: ScreenDecision
  scores: Scores
  gap: Gap
  legs: Legs
}
export interface ObserveRequest extends Scoped {
  source: Source
}
export interface ObserveResponse {
  version: number
  legs: Legs
}
export type StatusRequest = Scoped
export interface StatusResponse {
  version: number
  legs: Legs
  classifier: ClassifierState
}
export interface HealthRequest {
  version: number
}
export interface HealthResponse {
  version: number
  state: Health
}
export interface ErrorResponse {
  version: number
  error: Code
}

export interface Requests {
  register: RegisterRequest
  preregister: PreregisterRequest
  gate: GateRequest
  decide: DecideRequest
  screen: ScreenRequest
  observe: ObserveRequest
  status: StatusRequest
  health: HealthRequest
}
export interface Responses {
  register: RegisterResponse
  preregister: PreregisterResponse
  gate: GateResponse
  decide: DecideResponse
  screen: ScreenResponse
  observe: ObserveResponse
  status: StatusResponse
  health: HealthResponse
}

// ProtoError is a failed decode or encode, carrying only its code.
export class ProtoError extends Error {
  code: Code
  constructor(code: Code) {
    super(`barmkin proto: ${code}`)
    this.code = code
  }
}

export function opPath(op: Op): string {
  return PATH_PREFIX + op
}

// parsePath returns the operation an exact request path names.
export function parsePath(path: string): Op | undefined {
  if (!path.startsWith(PATH_PREFIX)) return undefined
  const name = path.slice(PATH_PREFIX.length)
  return OPS.find((op) => op === name)
}

// Shapes list each message's fields in wire order. Every field is required.
type Shape = "int" | "number" | "bool" | "string" | { array: Shape } | { object: Readonly<Record<string, Shape>> }

const LEGS: Shape = { object: { untrusted: "string", sensitive: "string" } }
const SCORES: Shape = { object: { injection: "number", credentials: "number", exfiltration: "number" } }
const SCOPED = { version: "int", host: "string", session: "string" } as const
const CLASS_LIST: Shape = { array: "string" }

const REQUEST_SHAPES: Readonly<Record<Op, Shape>> = {
  register: {
    object: {
      ...SCOPED,
      root: "string",
      fresh: "bool",
      posture: { object: { sandbox_enabled: "bool", allow_all_unix_sockets: "bool" } },
    },
  },
  preregister: { object: { ...SCOPED, call: "string" } },
  gate: { object: { ...SCOPED, call: "string" } },
  decide: { object: { ...SCOPED, classes: CLASS_LIST } },
  screen: { object: { ...SCOPED, source: "string", windows: { array: "string" }, scores: SCORES } },
  observe: { object: { ...SCOPED, source: "string" } },
  status: { object: SCOPED },
  health: { object: { version: "int" } },
}

const RESPONSE_SHAPES: Readonly<Record<Op, Shape>> = {
  register: { object: { version: "int", legs: LEGS } },
  preregister: { object: { version: "int", ttl_ms: "int" } },
  gate: { object: { version: "int", preregistered: "bool" } },
  decide: { object: { version: "int", verdict: "string", rule: "string", classes: CLASS_LIST, legs: LEGS } },
  screen: { object: { version: "int", decision: "string", scores: SCORES, gap: "string", legs: LEGS } },
  observe: { object: { version: "int", legs: LEGS } },
  status: { object: { version: "int", legs: LEGS, classifier: "string" } },
  health: { object: { version: "int", state: "string" } },
}

const ERROR_SHAPE: Shape = { object: { version: "int", error: "string" } }

// Semantic checks, applied once a message has its shape. They mirror the
// validate methods in internal/proto/decode.go.

const TOKEN = /^[A-Za-z0-9._-]{1,128}$/

const oneOf = (v: unknown, set: readonly unknown[]) => set.includes(v)
const untrustedFromShim = (s: unknown) => oneOf(s, UNTRUSTED_SHIM_SOURCES)

function validLegs(l: Legs): boolean {
  const untrusted = l.untrusted === "none" || untrustedFromShim(l.untrusted) || oneOf(l.untrusted, UNTRUSTED_MONITOR_SOURCES)
  return untrusted && oneOf(l.sensitive, ["none", "credential"])
}

const validClasses = (cs: readonly string[]) => cs.every((c) => oneOf(c, CLASSES)) && new Set(cs).size === cs.length

const validScores = (s: Scores) => [s.injection, s.credentials, s.exfiltration].every((p) => p >= 0 && p <= 1)

const validWindows = (ws: readonly string[]) =>
  ws.length > 0 && ws.length <= MAX_WINDOWS && ws.every((w) => w.length > 0 && w.length <= MAX_WINDOW_SIZE)

const scoped = (m: Scoped) => m.version === VERSION && oneOf(m.host, HOSTS) && TOKEN.test(m.session)

type Check<T> = (m: T) => boolean

const REQUEST_CHECKS: { [O in Op]: Check<Requests[O]> } = {
  register: (m) => scoped(m) && TOKEN.test(m.root),
  preregister: (m) => scoped(m) && TOKEN.test(m.call),
  gate: (m) => scoped(m) && TOKEN.test(m.call),
  decide: (m) => scoped(m) && validClasses(m.classes),
  screen: (m) => scoped(m) && untrustedFromShim(m.source) && validWindows(m.windows) && validScores(m.scores),
  observe: (m) => scoped(m) && (untrustedFromShim(m.source) || m.source === "credential"),
  status: (m) => scoped(m),
  health: (m) => m.version === VERSION,
}

function consistentVerdict(m: DecideResponse): boolean {
  switch (m.verdict) {
    case "pass":
      return m.rule === "none" && m.classes.length === 0
    case "warn":
      return m.classes.length > 0
    case "deny":
      return m.rule !== "none" && m.classes.length > 0
  }
  return false
}

const RESPONSE_CHECKS: { [O in Op]: Check<Responses[O]> } = {
  register: (m) => m.version === VERSION && validLegs(m.legs),
  preregister: (m) => m.version === VERSION && m.ttl_ms > 0,
  gate: (m) => m.version === VERSION,
  decide: (m) =>
    m.version === VERSION &&
    consistentVerdict(m) &&
    oneOf(m.rule, ["none", "untrusted", "rule_of_two"]) &&
    validClasses(m.classes) &&
    validLegs(m.legs),
  screen: (m) =>
    m.version === VERSION &&
    oneOf(m.decision, ["pass", "escalate", "deny"]) &&
    validScores(m.scores) &&
    oneOf(m.gap, ["none", "scan_limit", "unclassified"]) &&
    validLegs(m.legs),
  observe: (m) => m.version === VERSION && validLegs(m.legs),
  status: (m) => m.version === VERSION && validLegs(m.legs) && oneOf(m.classifier, ["ok", "degraded"]),
  health: (m) => m.version === VERSION && oneOf(m.state, ["ok", "degraded"]),
}

const checkError: Check<ErrorResponse> = (m) => m.version === VERSION && oneOf(m.error, CODES)

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}

// fits checks v against s: exactly the listed keys, the right types, and no
// null anywhere.
function fits(v: unknown, s: Shape): boolean {
  switch (s) {
    case "int":
      return Number.isInteger(v)
    case "number":
      return typeof v === "number"
    case "bool":
      return typeof v === "boolean"
    case "string":
      return typeof v === "string"
  }
  if ("array" in s) return Array.isArray(v) && v.every((e) => fits(e, s.array))
  if (!isObject(v)) return false
  const want = Object.keys(s.object)
  return Object.keys(v).length === want.length && want.every((k) => Object.hasOwn(v, k) && fits(v[k], s.object[k]))
}

// hasRepeatedKey reports whether any object in valid JSON text repeats a
// key. JSON.parse keeps the last value of a repeated key, so it cannot tell.
function hasRepeatedKey(text: string): boolean {
  const stack: (Set<string> | null)[] = [] // a key set per object, null per array
  let atKey = false
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]
    if (ch === '"') {
      let j = i + 1
      while (text[j] !== '"') j += text[j] === "\\" ? 2 : 1
      const keys = stack[stack.length - 1]
      if (atKey && keys) {
        const key = JSON.parse(text.slice(i, j + 1)) as string
        if (keys.has(key)) return true
        keys.add(key)
      }
      atKey = false
      i = j
    } else if (ch === "{") {
      stack.push(new Set())
      atKey = true
    } else if (ch === "[") {
      stack.push(null)
    } else if (ch === "}" || ch === "]") {
      stack.pop()
    } else if (ch === ",") {
      atKey = stack[stack.length - 1] != null
    }
  }
  return false
}

// decodeWith strictly decodes raw. Like the Go decoder, it checks the
// version before the rest of the shape, so a message from another version
// is a mismatch even if its fields differ. Unlike it, JSON.parse cannot
// tell 1.0 from 1, so an integer field written as 1.0 is accepted here.
function decodeWith<T>(raw: string, shape: Shape, check: Check<T>): T {
  if (new TextEncoder().encode(raw).length > MAX_BODY_BYTES) throw new ProtoError("bad_request")
  let v: unknown
  try {
    v = JSON.parse(raw)
  } catch {
    throw new ProtoError("bad_request")
  }
  if (isObject(v) && Number.isInteger(v.version) && v.version !== VERSION) throw new ProtoError("version_mismatch")
  if (hasRepeatedKey(raw) || !fits(v, shape) || !check(v as T)) throw new ProtoError("bad_request")
  return v as T
}

// ordered copies v with its keys in s's wire order.
function ordered(v: unknown, s: Shape): unknown {
  if (typeof s === "string") return v
  if ("array" in s) return (v as unknown[]).map((e) => ordered(e, s.array))
  const o = v as Record<string, unknown>
  return Object.fromEntries(Object.keys(s.object).map((k) => [k, ordered(o[k], s.object[k])]))
}

function encodeWith<T>(m: T, shape: Shape, check: Check<T>): string {
  if (!fits(m, shape) || !check(m)) throw new ProtoError("bad_request")
  return JSON.stringify(ordered(m, shape))
}

export function decodeRequest<O extends Op>(op: O, raw: string): Requests[O] {
  return decodeWith(raw, REQUEST_SHAPES[op], REQUEST_CHECKS[op] as Check<Requests[O]>)
}

export function decodeResponse<O extends Op>(op: O, raw: string): Responses[O] {
  return decodeWith(raw, RESPONSE_SHAPES[op], RESPONSE_CHECKS[op] as Check<Responses[O]>)
}

export function decodeError(raw: string): ErrorResponse {
  return decodeWith(raw, ERROR_SHAPE, checkError)
}

export function encodeRequest<O extends Op>(op: O, m: Requests[O]): string {
  return encodeWith(m, REQUEST_SHAPES[op], REQUEST_CHECKS[op] as Check<Requests[O]>)
}

export function encodeResponse<O extends Op>(op: O, m: Responses[O]): string {
  return encodeWith(m, RESPONSE_SHAPES[op], RESPONSE_CHECKS[op] as Check<Responses[O]>)
}

export function encodeError(m: ErrorResponse): string {
  return encodeWith(m, ERROR_SHAPE, checkError)
}
