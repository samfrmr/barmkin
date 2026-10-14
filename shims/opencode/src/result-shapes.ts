// OpenCode 2.x wire shapes for the hooks the shim reads or rewrites, and the
// pure traversals over them. No `$`, no plugin runtime import: the shapes are
// declared structurally (mirroring @opencode/plugin 2.0.27 `dist/promise/{tool,
// session}.d.ts`) so the shared library and the tests need no OpenCode package.
//
// Evidence tags: V<n> is a lab check of the re-scout ledger (data/opencode-port-
// 2x-rescout/report.md section 7.1, real 2.0.27 binary); S<n> is its source
// index; "typed" means the shape comes from the 2.0.27 plugin `.d.ts` and was
// not lab-run for that exact site. A site with only "typed" evidence is
// best-effort: the adapter must treat a missing or oddly shaped field as "no
// text to screen", never throw (a throw in a transform disables the plugin,
// V19; a throw in a hook other than execute.before and permission.evaluate does
// not deny).
//
// Unlike Claude Code's tool.call, OpenCode 2.x has no in-place-args trap: an
// execute.after `result` can be mutated in place or replaced wholesale and both
// take effect, on the model's copy and the stored copy (V4, V20, V21).

// ---------------------------------------------------------------------------
// tool.execute.after
// ---------------------------------------------------------------------------

export type ToolContentPart =
  | { type: 'text'; text: string }
  | { type: 'file'; uri: string; mime: string; name?: string }

// Tool.Result. `content` is what the model reads; `output` is the structured
// value the UI and the store keep. Both are screened and redacted, because the
// store keeps `output` and a later plugin or client may show it (V20).
// Observed per tool (V20, V24, V30, V31, V33):
//   shell     output { exit, truncated, output: string, status } + content[text, "Exited with code N"]
//   webfetch  output { url, contentType, format, output: string } + content[text]
//   MCP       output string + content[text]  (raw text or structured output)
//   skill     output { name, directory, output: "<skill_content ...>" } + content[text]
//   execute   output { output: string, toolCalls: [...], files: [] } + content[text]  (Code Mode)
//   read/edit/write/patch: same envelope; payload under output and/or content.
export interface ToolResult {
  output?: unknown
  content?: string | readonly ToolContentPart[]
  metadata?: Record<string, unknown>
}

// Tool.Error. A class instance (`_tag: 'Tool.Error'`) whose `message` is the
// text the model reads. Only an in-place `message` assignment is lab-verified
// (V21); do not rebuild the object.
export interface ToolError {
  _tag?: string
  message: string
  error?: unknown
  metadata?: Record<string, unknown>
}

export interface ToolAfterBase {
  tool: string
  sessionID: string
  agent?: string
  messageID?: string
  id?: string
  // The arguments as the tool ran them, after every before-hook rewrite (V3, V4).
  input: unknown
}

// execute.after fires on success AND on failure (V21), so the error path is
// hooked the same as the success path.
export type ToolAfterEvent = ToolAfterBase &
  ({ status: 'completed'; result: ToolResult } | { status: 'error'; error: ToolError })

export type ToolAfterCompleted = ToolAfterBase & { status: 'completed'; result: ToolResult }
export type ToolAfterError = ToolAfterBase & { status: 'error'; error: ToolError }

export function isToolAfterCompleted(event: unknown): event is ToolAfterCompleted {
  const e = event as { status?: unknown; result?: unknown } | null
  return !!e && e.status === 'completed' && !!e.result && typeof e.result === 'object'
}

export function isToolAfterError(event: unknown): event is ToolAfterError {
  const e = event as { status?: unknown; error?: unknown } | null
  return !!e && e.status === 'error' && !!e.error && typeof (e.error as { message?: unknown }).message === 'string'
}

// ---------------------------------------------------------------------------
// session.context, session.title, session.compaction, session.generate
// ---------------------------------------------------------------------------

export interface SystemPart {
  type: 'text'
  text: string
  cache?: unknown
  metadata?: Record<string, unknown>
}

// A model-bound message. `content` is a ContentPart[]: text, media, tool-call
// (`input`), tool-result (`result: { type: json|text|error|content, value }`),
// reasoning, and compaction parts (typed, messages.d.ts). Synthetic messages
// (a background shell's `<shell ...>` output, the MCP "catalog has changed"
// notice) arrive as ordinary user-role text, with no marker (V23, V30).
export interface ContextMessage {
  role: 'system' | 'user' | 'assistant' | 'tool'
  content: unknown
  [key: string]: unknown
}

export interface ToolDescription {
  description: string
  input?: unknown
}

// The request every model call carries. All four hooks below share it.
export interface SessionRequestShape {
  sessionID: string
  system: SystemPart[]
  messages: ContextMessage[]
}

// session.context: before each primary request. `tools` is the model's tool
// list with descriptions (V23 reached MCP descriptions via tool.transform; the
// `tools` record here is typed). `system` and `messages` rewrites are
// lab-verified: assigning a rewritten copy removed every raw copy of a
// prompt-borne secret from all three model requests (V28).
export interface SessionContextShape extends SessionRequestShape {
  agent?: string
  tools: Record<string, ToolDescription>
}

// session.title: the title side call, which 1.x could not reach. `system` and
// `messages` rewritten the same way (V28). `result`, when set, skips the model
// request; the shim never sets it.
export interface SessionTitleShape extends SessionRequestShape {
  result?: string
}

// session.compaction: a SessionContext plus `result`. Typed only; the request
// side is rewritten like the context (same SessionRequest fields). A `result`
// set by an earlier plugin carries a summary that goes into history unseen by
// the context hook, so it is mapped too.
export interface SessionCompactionShape extends SessionContextShape {
  result?: { summary: string; providerState?: unknown; metadata?: Record<string, unknown>; tokens?: unknown }
}

// session.generate: a SessionContext used for plugin- or API-initiated
// generations. Typed only; same handling as the context.
export type SessionGenerateShape = SessionContextShape

// session.prompt: the person's turn as it enters the session. Carries NO
// origin (V27): keys are `sessionID, messageID, prompt, metadata, delivery`,
// so a human-typed prompt cannot be told from a synthetic one here. `prompt`
// is typed DeepMutable, so `prompt.text` is assignable; only the throw
// (refuse the turn, V26) is lab-verified.
export interface SessionPromptShape {
  sessionID: string
  messageID?: string
  prompt: { text: string; files?: Array<{ uri: string; name?: string; description?: string }>; [key: string]: unknown }
  metadata?: Record<string, unknown>
  delivery?: string
}

// ---------------------------------------------------------------------------
// Pure traversals
// ---------------------------------------------------------------------------

export type StringMap = (s: string) => string

// Objects the traversal must hand back untouched: typed arrays and binary
// buffers (media bytes), and platform value objects.
function isOpaque(value: object): boolean {
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return true
  return (
    value instanceof Date ||
    value instanceof RegExp ||
    value instanceof Map ||
    value instanceof Set ||
    (typeof URL !== 'undefined' && value instanceof URL) ||
    (typeof Request !== 'undefined' && value instanceof Request) ||
    (typeof Response !== 'undefined' && value instanceof Response) ||
    (typeof Blob !== 'undefined' && value instanceof Blob) ||
    (typeof Headers !== 'undefined' && value instanceof Headers)
  )
}

// Applies `fn` to every string in a JSON-like tree, returning a new tree and
// leaving the input untouched. Plain objects, arrays and class instances (the
// 2.x Message and Tool.Error classes) are rebuilt with their prototype kept;
// opaque binary and platform objects pass through. Strings under keys listed
// in `skipKeys` are copied verbatim (protocol discriminants a redaction rule
// must not rewrite). Cycles map to the already-built copy.
export function mapStrings<T>(value: T, fn: StringMap, skipKeys: ReadonlySet<string> = DEFAULT_SKIP_KEYS): T {
  const seen = new WeakMap<object, unknown>()
  const walk = (v: unknown, key: string | null): unknown => {
    if (typeof v === 'string') return key !== null && skipKeys.has(key) ? v : fn(v)
    if (v === null || typeof v !== 'object') return v
    if (isOpaque(v as object)) return v
    const hit = seen.get(v as object)
    if (hit !== undefined) return hit
    if (Array.isArray(v)) {
      const out: unknown[] = []
      seen.set(v, out)
      for (const item of v) out.push(walk(item, key))
      return out
    }
    const out = Object.create(Object.getPrototypeOf(v)) as Record<string, unknown>
    seen.set(v as object, out)
    for (const k of Object.keys(v as object)) out[k] = walk((v as Record<string, unknown>)[k], k)
    return out
  }
  return walk(value, null) as T
}

// Keys whose string values are protocol discriminants, never payload:
// rewriting them could corrupt the request. Payload keys (`id`, `name`, `uri`,
// a tool's own `type` field) are NOT skipped where the tree is tool output.
const DEFAULT_SKIP_KEYS: ReadonlySet<string> = new Set(['type', 'role', 'mime'])
const NO_SKIP_KEYS: ReadonlySet<string> = new Set()
const CONTENT_SKIP_KEYS: ReadonlySet<string> = new Set(['type', 'mime', 'uri'])

// Wraps `fn` so a caller can learn whether anything changed, and only assign
// back when something did.
function tracked(fn: StringMap): { fn: StringMap; changed: () => boolean } {
  let changed = false
  return {
    fn: (s) => {
      const out = fn(s)
      if (out !== s) changed = true
      return out
    },
    changed: () => changed,
  }
}

// execute.after, completed (V20): a rewritten copy of every string in
// `output`, `content` and `metadata`. Wholesale replacement is verified (V20,
// `replace` mode). File parts' `uri`/`mime`/`type` are left alone.
export function mapResultStrings(result: ToolResult, fn: StringMap): ToolResult {
  const out: ToolResult = {}
  if ('output' in result) out.output = mapStrings(result.output, fn, NO_SKIP_KEYS)
  if ('content' in result) {
    out.content = typeof result.content === 'string' ? fn(result.content) : mapStrings(result.content, fn, CONTENT_SKIP_KEYS)
  }
  if ('metadata' in result) out.metadata = mapStrings(result.metadata, fn, NO_SKIP_KEYS)
  return out
}

// execute.after, error (V21): rewrites `error.message` IN PLACE, the one
// mutation lab-verified to reach both the model and the store. `metadata` is a
// best-effort in-place rewrite (typed, not lab-run). Returns whether anything
// changed. A frozen or accessor-only field is swallowed; the context net
// (mapRequestStrings) is then the remaining line.
export function mapErrorStrings(error: ToolError, fn: StringMap): boolean {
  const t = tracked(fn)
  try {
    const message = t.fn(error.message)
    if (message !== error.message) error.message = message
  } catch {
    return false
  }
  if (error.metadata && typeof error.metadata === 'object') {
    try {
      const metadata = mapStrings(error.metadata, t.fn, NO_SKIP_KEYS)
      if (t.changed()) error.metadata = metadata
    } catch {
      // leave metadata as it was
    }
  }
  return t.changed()
}

const ENVELOPE_KEYS: ReadonlySet<string> = new Set(['type', 'role', 'mime'])
const PAYLOAD_KEYS: ReadonlySet<string> = new Set(['input', 'output', 'value', 'metadata'])

// Rewrites a message or system tree: `type`/`role`/`mime` strings on the
// content-part envelope are kept, while tool-call `input` and tool-result
// `result` (bar its own `type`) are payload and walked with no key skipping.
function mapEnvelope(value: unknown, fn: StringMap): unknown {
  if (typeof value === 'string') return fn(value)
  if (value === null || typeof value !== 'object' || isOpaque(value as object)) return value
  if (Array.isArray(value)) return value.map((item) => mapEnvelope(item, fn))
  const rec = value as Record<string, unknown>
  const out = Object.create(Object.getPrototypeOf(value)) as Record<string, unknown>
  for (const k of Object.keys(rec)) {
    const v = rec[k]
    if (typeof v === 'string' && ENVELOPE_KEYS.has(k)) out[k] = v
    else if (PAYLOAD_KEYS.has(k)) out[k] = mapStrings(v, fn, NO_SKIP_KEYS)
    else if (k === 'result' && v && typeof v === 'object' && !Array.isArray(v)) {
      const r = v as Record<string, unknown>
      const copy = Object.create(Object.getPrototypeOf(v)) as Record<string, unknown>
      for (const rk of Object.keys(r)) copy[rk] = rk === 'type' && typeof r[rk] === 'string' ? r[rk] : mapStrings(r[rk], fn, NO_SKIP_KEYS)
      out[k] = copy
    } else out[k] = mapEnvelope(v, fn)
  }
  return out
}

// session.context / title / compaction / generate (V28): assigns rewritten
// copies of `system` and `messages`. Message ids, roles and part `type`s are
// skipped. Assigning a deep copy is the verified mechanism (V28 used a JSON
// round trip); this copy also keeps binary media and class prototypes. Returns
// whether anything changed.
export function mapRequestStrings(event: SessionRequestShape, fn: StringMap): boolean {
  let changed = false
  for (const field of ['system', 'messages'] as const) {
    const current = event[field]
    if (!Array.isArray(current)) continue
    const t = tracked(fn)
    const next = mapEnvelope(current, t.fn)
    if (t.changed()) {
      ;(event as unknown as Record<string, unknown>)[field] = next
      changed = true
    }
  }
  return changed
}

// session.context `tools`: rewrites each tool's top-level `description` in
// place and, when `schemas` is set, every `description` string inside its JSON
// input schema (an MCP parameter description reaches the model too). The
// top-level description path is the V23 mechanism (tool.transform); the
// `session.context.tools` record and schema descriptions are typed only.
// Returns the ids rewritten.
export function mapToolDescriptions(
  tools: Record<string, ToolDescription> | undefined,
  fn: StringMap,
  schemas = true,
): string[] {
  const touched: string[] = []
  if (!tools || typeof tools !== 'object') return touched
  for (const [id, tool] of Object.entries(tools)) {
    if (!tool || typeof tool !== 'object') continue
    let changed = false
    try {
      if (typeof tool.description === 'string') {
        const d = fn(tool.description)
        if (d !== tool.description) {
          tool.description = d
          changed = true
        }
      }
      if (schemas && tool.input && typeof tool.input === 'object') changed = rewriteSchemaDescriptions(tool.input, fn) || changed
    } catch {
      continue
    }
    if (changed) touched.push(id)
  }
  return touched
}

function rewriteSchemaDescriptions(node: unknown, fn: StringMap, depth = 0): boolean {
  if (!node || typeof node !== 'object' || depth > 24) return false
  let changed = false
  if (Array.isArray(node)) {
    for (const item of node) changed = rewriteSchemaDescriptions(item, fn, depth + 1) || changed
    return changed
  }
  const rec = node as Record<string, unknown>
  for (const key of Object.keys(rec)) {
    const v = rec[key]
    if ((key === 'description' || key === 'title') && typeof v === 'string') {
      const out = fn(v)
      if (out !== v) {
        rec[key] = out
        changed = true
      }
    } else if (v && typeof v === 'object') {
      changed = rewriteSchemaDescriptions(v, fn, depth + 1) || changed
    }
  }
  return changed
}

// session.compaction `result` set by an earlier plugin: its summary enters
// history without passing the context hook. Typed only.
export function mapCompactionResult(event: SessionCompactionShape, fn: StringMap): boolean {
  const result = event.result
  if (!result || typeof result.summary !== 'string') return false
  const summary = fn(result.summary)
  if (summary === result.summary) return false
  result.summary = summary
  return true
}

// session.prompt: the prompt text and any attached file's name/description.
// Assigning `prompt.text` is typed (DeepMutable), not lab-run; the verified
// action on this hook is a refusing throw (V26). Returns whether it changed.
export function mapPromptStrings(event: SessionPromptShape, fn: StringMap): boolean {
  const prompt = event.prompt
  if (!prompt || typeof prompt !== 'object') return false
  let changed = false
  if (typeof prompt.text === 'string') {
    const text = fn(prompt.text)
    if (text !== prompt.text) {
      prompt.text = text
      changed = true
    }
  }
  for (const file of Array.isArray(prompt.files) ? prompt.files : []) {
    for (const field of ['name', 'description'] as const) {
      const v = file?.[field]
      if (typeof v === 'string') {
        const out = fn(v)
        if (out !== v) {
          file[field] = out
          changed = true
        }
      }
    }
  }
  return changed
}

// ---------------------------------------------------------------------------
// Reading text for the screens
// ---------------------------------------------------------------------------

export interface ContextText {
  where: 'system' | 'message' | 'tool'
  // Role of the message ('system' for the system prompt, tool id for tools).
  role: string
  index: number
  text: string
  // True for a user-role text that looks like an OpenCode-authored notice
  // rather than a person's turn: a background shell's `<shell ...>` output (V30).
  // The MCP "catalog has changed" notice has no stable marker (V23): screen
  // every non-first user message from `session.context`, not just this flag.
  synthetic: boolean
}

const SYNTHETIC_PREFIX = /^\s*<(?:shell|subagent)\b/

function partTexts(content: unknown): string[] {
  if (typeof content === 'string') return [content]
  if (!Array.isArray(content)) return []
  const out: string[] = []
  for (const part of content) {
    if (typeof part === 'string') out.push(part)
    else if (part && typeof part === 'object') {
      const p = part as { type?: unknown; text?: unknown; result?: { value?: unknown }; input?: unknown }
      if (typeof p.text === 'string') out.push(p.text)
      else if (p.type === 'tool-result' && p.result) out.push(...jsonTexts(p.result.value))
      else if (p.type === 'tool-call') out.push(...jsonTexts(p.input))
    }
  }
  return out
}

function jsonTexts(value: unknown): string[] {
  if (typeof value === 'string') return [value]
  if (Array.isArray(value)) return value.flatMap(jsonTexts)
  if (value && typeof value === 'object') return Object.values(value as object).flatMap(jsonTexts)
  return []
}

// Every text a request will put in front of the model: the system prompt,
// each message's text and tool-result parts, and each tool description. This
// is the input of the context-time screens (instructions in MCP server
// `instructions`, skill listings, synthetic notices; V23, V30, V31).
export function contextTexts(event: Partial<SessionContextShape>): ContextText[] {
  const out: ContextText[] = []
  for (const [index, part] of (Array.isArray(event.system) ? event.system : []).entries()) {
    if (part && typeof part.text === 'string') out.push({ where: 'system', role: 'system', index, text: part.text, synthetic: false })
  }
  for (const [index, message] of (Array.isArray(event.messages) ? event.messages : []).entries()) {
    const role = typeof message?.role === 'string' ? message.role : 'unknown'
    for (const text of partTexts(message?.content)) {
      out.push({ where: 'message', role, index, text, synthetic: role === 'user' && SYNTHETIC_PREFIX.test(text) })
    }
  }
  for (const [id, tool] of Object.entries(event.tools ?? {})) {
    if (tool && typeof tool.description === 'string') out.push({ where: 'tool', role: id, index: 0, text: tool.description, synthetic: false })
  }
  return out
}

export function promptText(event: Partial<SessionPromptShape>): string {
  return typeof event.prompt?.text === 'string' ? event.prompt.text : ''
}
