// barmkin-opencode: the barmkin shim for OpenCode 2.x, connected to the barmkin
// monitor. A port of barmkin-mod's OpenCode plugin (samfrmr/barmkin-mod
// opencode/server.ts) in which the monitor holds every session's taint.
//
// `export default { id, setup(ctx) }` is OpenCode 2's Promise-API plugin entry
// (re-scout section 2.1). Everything host-neutral comes from the library the
// Claude Code shim uses (src/lib.ts); this file is only the host adapter: it
// wires the 2.x hooks and composes the library the way the Claude Code shim's
// hooks/register.ts does. NOT equivalent to barmkin-mod for Claude Code: see the
// posture line this file emits and the contract in README.md.
//
// The monitor (internal/monitor, reached over HTTP on its Unix socket through
// the contract in ../common/proto.ts) owns the session: its two legs
// (untrusted and sensitive), the egress decision over them, and the screen of
// untrusted content. Each OpenCode session registers as a monitor session in
// the lineage of its root session (a subagent's session shares its parent's
// legs), so the taint lives in the monitor, per root, and survives an OpenCode
// restart and a monitor restart. Nothing in this process holds a taint of its
// own: the per-root view below is a read-through cache for the status
// surface, which never waits on the monitor.
//
// Legs only rise. Nothing in the shim or the monitor lowers one: no prompt,
// command or compaction clears the taint, and only a new session starts clean.
//
// The shim keeps what needs the content, which never leaves it except as
// redacted screen windows: secret redaction and the invisible-text scrub,
// classifying calls into egress class ids, the MCP and skill guards, the
// posture line and the status channel to the TUI half.
//
// Rules this file follows (CONTRACT.md, re-scout V-set):
//  - Deny = throw. A throw in `tool.execute.before` stops the tool and the model
//    reads the thrown text (V2). A throw in `permission.evaluate` is final even
//    when a later plugin forces "allow" (V7); setting `effect = "deny"` is NOT
//    final (V6), so it is never used.
//  - Never throw inside a `*.transform` callback (V19): OpenCode disables the
//    whole plugin mid-session.
//  - Hooks that guard fail closed: a monitor request that fails, times out or
//    gets a malformed answer, and any internal failure, refuses the call
//    (before hooks, evaluate, the model request) or withholds the result
//    (after hook). An unreachable or unknown monitor never lets a guarded call
//    through.
//  - `setup` itself only throws for a guard hook that could not be registered;
//    everything optional (rpc, the plugin-inventory probe) is isolated, and
//    setup never waits on the monitor.
//
// Environment variables:
//   BARMKIN_MONITOR_SOCKET   monitor Unix socket path (required)
//
// Plugin options:
//   sandboxed              true only when OpenCode itself runs inside an OS
//                          sandbox whose tools cannot reach the monitor socket.
//                          OpenCode 2 has no sandbox of its own, so without it
//                          the monitor refuses every session (posture_refused)
//                          and every guarded call is denied.
//   mcp_server_allowlist   MCP server names, as an array or a comma-separated
//                          string; empty allows every server (audit-only).
//   debug                  log the guard's own failures to stderr.
import {
  REDACTION_RULES,
  redactInEitherView as redactInEitherViewLib,
  classifierInput,
  WITHHELD_TEXT,
  containsSecretInEitherView,
  measureResult,
  exceedsScreenedLimit,
  SCREENED_LIMIT_REASON,
  PAGING_ADVICE,
  scrubInvisible,
  isOutsideCwd,
  heuristicInjectionScore,
  UNTRUSTED_CONTENT_WARNING,
  describeVerdict,
  touchesSecretPath,
  SOURCE_TEXT,
  planWindows,
  skillBodyWithheldText,
  neutralizeSkillListing,
  type EgressCall,
  type EgressVerdict,
  type ShownLegs,
} from './src/lib'
import { classifyCalls, normaliseEgressCalls, normaliseEvaluate, type NormaliseOptions } from './src/egress-normaliser'
import { installMcpGuard, isServerAllowed, parseAllowlist, type McpFinding, type McpGuardHandle, type McpGuardHost, type SessionContextLike } from './src/mcp-guard'
import { mapPromptStrings, mapRequestStrings, mapToolDescriptions, mapCompactionResult, promptText, type SessionCompactionShape, type SessionContextShape, type SessionPromptShape, type ToolAfterEvent as WireAfterEvent } from './src/result-shapes'
import { statusRpc, type StatusReport } from './src/status-rpc'
import { afterEventText, noticeAfterEvent, redactAfterEvent, withholdAfterEvent } from './src/tool-result'
import { answerLegs, describeFailure, postMonitor, SOCKET_ENV, TOKEN, type Answer, type Failure } from './src/monitor'
import { VERSION, type Class, type Legs, type Op, type Posture, type Requests, type Scores, type Source } from '../common/proto.ts'

// ---------------------------------------------------------------------------
// Identity and the shipping text.
// ---------------------------------------------------------------------------

// Plugin id. Exactly this, never 'barmkin-mod' (that is the Claude plugin).
export const PLUGIN_ID = 'barmkin-opencode'
export const PLUGIN_VERSION = '0.1.0'

// The git sha the bundle was built from. The build injects it
// (`bun build --define BARMKIN_CORE_SHA='"<sha>"'`); an unbuilt checkout says so.
declare const BARMKIN_CORE_SHA: string | undefined
const CORE_SHA = typeof BARMKIN_CORE_SHA === 'string' && BARMKIN_CORE_SHA !== '' ? BARMKIN_CORE_SHA : 'unbuilt'

const HOST = 'opencode'

// More than this many invisible-text carriers (scrubInvisible's
// `hiddenCount`) stripped from one piece of content raise the untrusted leg.
const INVISIBLE_CHAR_TAINT_THRESHOLD = 32
// The inventory probe may wait on plugin activation, so it never blocks setup.
const INVENTORY_TIMEOUT_MS = 5_000
// A bound on each host lookup (session lineage and history): OpenCode puts no
// timeout on a plugin's own calls either.
const HOST_CALL_TIMEOUT_MS = 2_000

// Whether the MCP description neutraliser (src/mcp-guard) installed every hook it
// needs. Set in setup from the guard's own report; when it is false (the guard
// failed to install or an earlier step errored), the posture line says MCP tool
// descriptions are not covered.
let mcpDescriptionGuard = false
let mcpGuard: McpGuardHandle | null = null

function refreshMcpDescriptionGuard(): void {
  const status = mcpGuard?.status()
  mcpDescriptionGuard = status !== undefined && mcpGuard!.healthy() && status.installed.toolTransform && status.installed.contextHook
  if (status !== undefined && !mcpDescriptionGuard) debugLog('barmkin-opencode: the MCP guard is not fully installed: ' + status.errors.join('; '))
}

// ---------------------------------------------------------------------------
// The slice of the 2.x Promise-API context this file uses (OpenCode 2.0.28,
// @opencode/plugin promise/*.d.ts). Structural and local, so the bundle has no
// import from @opencode/*.
// ---------------------------------------------------------------------------

interface ToolBeforeEvent {
  tool: string
  readonly sessionID: string
  readonly agent: string
  readonly messageID: string
  readonly id: string
  input: unknown
}

type ToolAfterEvent = WireAfterEvent & { readonly agent: string; readonly messageID: string; readonly id: string }

interface PermissionEvaluation {
  readonly sessionID: string
  readonly action: string
  readonly resources: ReadonlyArray<string>
  readonly metadata?: Record<string, unknown>
  effect: string
  message?: string
}

// No session: OpenCode 2 does not say which session a shell belongs to.
interface ShellCreateBefore {
  command: string
  cwd: string
}

interface SessionPromptEvent {
  readonly sessionID: string
  prompt: unknown
}

interface SessionRequestEvent {
  readonly sessionID: string
}

interface PluginInfo {
  id?: string
  source: { type: string; path?: string; target?: string }
  state: { status: string; error?: string }
}

interface PluginContext {
  readonly options: Readonly<Record<string, any>>
  readonly location: { readonly directory: string }
  readonly tool: {
    hook(name: 'execute.before', callback: (event: ToolBeforeEvent) => Promise<void> | void): Promise<unknown>
    hook(name: 'execute.after', callback: (event: ToolAfterEvent) => Promise<void> | void): Promise<unknown>
    list(): Promise<ReadonlyArray<{ readonly id: string; readonly options?: { readonly namespace?: string } }>>
  }
  readonly permission: { hook(name: 'evaluate', callback: (event: PermissionEvaluation) => Promise<void> | void): Promise<unknown> }
  readonly shell: { hook(name: 'create.before', callback: (event: ShellCreateBefore) => Promise<void> | void): Promise<unknown> }
  readonly session: {
    hook(name: 'prompt', callback: (event: SessionPromptEvent) => Promise<void> | void): Promise<unknown>
    hook(name: 'context' | 'compaction' | 'generate' | 'title', callback: (event: SessionRequestEvent) => Promise<void> | void): Promise<unknown>
    get(input: { sessionID: string }): Promise<unknown>
    context(input: { sessionID: string }): Promise<unknown>
  }
  readonly plugin: { list(): Promise<unknown> }
  readonly rpc: { register(definition: unknown, handlers: unknown): Promise<unknown> }
}

let pluginOptions: Readonly<Record<string, any>> = {}
let projectDirectory = ''

// Redaction placeholder counters. Not security state (no secret value is ever
// kept, only a per-category count for unique labels). The model-boundary hooks
// use a fresh set on every pass instead: they re-run over the whole history each
// request, and a counter that keeps climbing would change the history's text
// between requests and defeat prompt caching.
const redactionCounters: Record<string, number> = {}

// The status RPC's change channel (src/status-rpc `changed`). Best effort: the TUI
// also polls, so a failed emit only delays its refresh.
let emitChanged: (reason: string) => void = () => {}

function debugLog(message: string): void {
  if (pluginOptions.debug === true) console.error(message)
}

function redactInEitherView(text: string, counters: Record<string, number> = redactionCounters): { text: string; redactedCount: number } {
  return redactInEitherViewLib(text, REDACTION_RULES, counters)
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {}
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

// A host call, bounded by HOST_CALL_TIMEOUT_MS.
async function bounded<T>(what: string, call: () => Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      call(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(what + ' timed out')), HOST_CALL_TIMEOUT_MS)
      }),
    ])
  } finally {
    clearTimeout(timer)
  }
}

// The host answers some calls as `{ data }` and some as the value itself.
function unwrap(value: unknown): unknown {
  return value && typeof value === 'object' && 'data' in value ? (value as { data: unknown }).data : value
}

// A bounded map: the oldest entry goes once it holds more than `max`.
function track<K, V>(map: Map<K, V>, key: K, value: V, max = 256): void {
  map.delete(key)
  map.set(key, value)
  if (map.size > max) {
    const oldest = map.keys().next().value
    if (oldest !== undefined) map.delete(oldest)
  }
}

// ---------------------------------------------------------------------------
// Sessions: each OpenCode session is a monitor session in its root's lineage.
// ---------------------------------------------------------------------------

const MAX_ROOT_DEPTH = 8
const MAX_TRACKED_SESSIONS = 4096

// session -> its root session, from the host's parent links. A lookup cache;
// the lineage itself lives in the monitor.
const rootCache = new Map<string, string>()

async function rootOf(ctx: PluginContext, sessionID: string): Promise<string> {
  const cached = rootCache.get(sessionID)
  if (cached !== undefined) return cached
  let current = sessionID
  for (let depth = 0; depth < MAX_ROOT_DEPTH; depth++) {
    let info: unknown
    try {
      info = unwrap(await bounded('the session lookup', () => ctx.session.get({ sessionID: current })))
    } catch (error) {
      throw new Error("barmkin-opencode: the session lineage lookup failed (" + errorText(error) + "), so the session's taint could not be resolved")
    }
    const parent = asRecord(info).parentID
    if (typeof parent !== 'string' || parent === '') break
    current = parent
  }
  track(rootCache, sessionID, current, MAX_TRACKED_SESSIONS)
  return current
}

// Message types that carry nothing but what the person chose: their own
// prompt and their agent, model and location switches.
const FRESH_MESSAGE_TYPES: ReadonlySet<string> = new Set(['user', 'agent-switched', 'model-switched', 'location-switched'])

// Whether a session is a brand-new top-level conversation: no parent, not a
// fork, and nothing in its history but the person's own messages. A resumed,
// forked or compacted session carries a history that may hold untrusted
// content, so it is not fresh, and neither is one whose history cannot be
// read. The monitor starts a lineage it has never seen tainted unless its
// root registers as fresh. By the session's first tool call the model's
// message is in the history, so the session registers at its first model
// request (see modelBoundary), while it still holds only the person's prompt.
async function isFreshSession(ctx: PluginContext, sessionID: string): Promise<boolean> {
  try {
    const info = asRecord(unwrap(await bounded('the session lookup', () => ctx.session.get({ sessionID }))))
    if (info.id !== sessionID || info.parentID !== undefined || info.fork !== undefined) return false
    const messages = unwrap(await bounded('the session history', () => ctx.session.context({ sessionID })))
    return Array.isArray(messages) && messages.every((m) => FRESH_MESSAGE_TYPES.has(String(asRecord(m).type)))
  } catch {
    return false
  }
}

// What the shim tells the monitor about how OpenCode runs its tools. OpenCode
// 2 has no tool sandbox, so an unsandboxed posture is the default, and the
// monitor refuses it: only an operator who runs OpenCode inside an OS sandbox
// whose tools cannot reach the monitor socket sets `sandboxed`.
function reportedPosture(): Posture {
  return { sandbox_enabled: pluginOptions.sandboxed === true, allow_all_unix_sockets: false }
}

function socketPath(): string {
  return process.env[SOCKET_ENV] ?? ''
}

// The local view of each root's lineage, for the status surface: the legs the
// monitor last reported, and why each leg rose as the shim saw it. The first
// reason recorded wins. The monitor never holds this text; it knows only the
// source. Every decision asks the monitor.
interface EgressRecord {
  tool: string
  classIds: string[]
  decision: 'deny' | 'warn'
  rule: string
  at: number
}

interface ScreenRecord {
  callId: string
  label: string
  decision: 'pass' | 'escalate' | 'deny'
  scores: Scores
  gap: 'none' | 'scan_limit' | 'unclassified'
  at: number
}

interface RootView {
  legs: Legs
  untrustedReason: string | null
  sensitiveReason: string | null
  lastEgress: EgressRecord | null
  lastScreen: ScreenRecord | null
}

const views = new Map<string, RootView>()
// The monitor's last answer: 'ok', or why the last request failed.
let monitorState = 'ok'

function viewOf(root: string): RootView {
  let view = views.get(root)
  if (view === undefined) {
    view = { legs: { untrusted: 'none', sensitive: 'none' }, untrustedReason: null, sensitiveReason: null, lastEgress: null, lastScreen: null }
    track(views, root, view, MAX_TRACKED_SESSIONS)
  }
  return view
}

// Records what a request found: the legs it reported, or why it failed.
function noteAnswer(root: string, answer: Answer<Op>): void {
  const before = monitorState
  monitorState = answer.ok ? 'ok' : answer.failure
  if (!answer.ok) {
    if (before !== monitorState) emitChanged('monitor')
    return
  }
  const legs = answerLegs(answer.value)
  if (!legs) return
  const view = viewOf(root)
  const raised = view.legs.untrusted !== legs.untrusted || view.legs.sensitive !== legs.sensitive
  view.legs = { ...legs }
  if (raised || before !== monitorState) emitChanged('taint')
}

function noteReason(root: string, leg: 'untrusted' | 'sensitive', reason: string): void {
  const view = viewOf(root)
  if (leg === 'sensitive') view.sensitiveReason ??= reason
  else view.untrustedReason ??= reason
}

function shownLegs(root: string, legs: Legs): ShownLegs {
  const view = viewOf(root)
  return {
    untrusted: legs.untrusted,
    sensitive: legs.sensitive,
    untrustedReason: legs.untrusted === 'none' ? null : view.untrustedReason,
    sensitiveReason: legs.sensitive === 'none' ? null : view.sensitiveReason,
  }
}

// Sessions this process registered, and the registrations in flight, so
// concurrent hooks send one register per session.
const registered = new Set<string>()
const registering = new Map<string, Promise<Answer<'register'>>>()

function registerSession(ctx: PluginContext, session: string): Promise<Answer<'register'>> {
  const pending = registering.get(session)
  if (pending) return pending
  const run = sendRegister(ctx, session).finally(() => registering.delete(session))
  registering.set(session, run)
  return run
}

// Registers a session in its root's lineage. Only a root can be fresh: a
// lineage the monitor has never seen that is not fresh starts with its
// untrusted leg raised, because its history is not known to be clean, and a
// lineage it knows keeps its legs.
async function sendRegister(ctx: PluginContext, session: string): Promise<Answer<'register'>> {
  const root = await rootOf(ctx, session)
  if (!TOKEN.test(root)) return { ok: false, failure: 'bad_request' }
  const fresh = root === session && (await isFreshSession(ctx, session))
  const answer = await postMonitor(socketPath(), 'register', { version: VERSION, host: HOST, session, root, fresh, posture: reportedPosture() })
  noteAnswer(root, answer)
  if (answer.ok) {
    registered.add(session)
    if (registered.size > MAX_TRACKED_SESSIONS) registered.delete(registered.values().next().value as string)
  }
  return answer
}

// One request about a session. The session is registered first if this
// process has not registered it yet, and once more if the monitor no longer
// knows it (a monitor that lost its journal).
async function sessionRequest<O extends Exclude<Op, 'register' | 'health'>>(
  ctx: PluginContext,
  session: string,
  op: O,
  fields: Omit<Requests[O], 'version' | 'host' | 'session'>,
): Promise<Answer<O>> {
  if (!TOKEN.test(session)) return { ok: false, failure: 'bad_request' }
  for (let attempt = 0; ; attempt++) {
    if (!registered.has(session)) {
      const reg = await registerSession(ctx, session)
      if (!reg.ok) return reg
    }
    const answer = await postMonitor(socketPath(), op, { version: VERSION, host: HOST, session, ...fields } as unknown as Requests[O])
    if (!answer.ok && answer.failure === 'unknown_session' && attempt === 0) {
      registered.delete(session)
      continue
    }
    noteAnswer(await rootOf(ctx, session), answer)
    return answer
  }
}

// Raises a leg for an event the shim detected itself, and records why. The
// first reason recorded for a leg wins. A leg the monitor already reported up
// for this registered session is not asked again: legs only rise, so the
// answer could not change.
async function observe(ctx: PluginContext, session: string, source: Source, reason: string): Promise<Answer<'observe'>> {
  const leg = source === 'credential' ? 'sensitive' : 'untrusted'
  const view = registered.has(session) ? views.get(await rootOf(ctx, session)) : undefined
  if (view !== undefined && view.legs[leg] !== 'none') return { ok: true, value: { version: VERSION, legs: { ...view.legs } } }
  const answer = await sessionRequest(ctx, session, 'observe', { source })
  if (answer.ok) noteReason(await rootOf(ctx, session), leg, reason)
  return answer
}

// What a step guarded by the monitor says when the monitor did not answer it.
function failureText(what: string, failure: Failure): string {
  return 'barmkin-opencode: ' + what + ' was denied because ' + describeFailure(failure) + '.'
}

// Raises the untrusted leg when a scrub stripped more than
// INVISIBLE_CHAR_TAINT_THRESHOLD characters. Returns the failure if the
// monitor could not record it.
async function taintForScrub(ctx: PluginContext, session: string, hiddenCount: number, what: string): Promise<Failure | null> {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return null
  const answer = await observe(ctx, session, 'invisible', 'stripped ' + hiddenCount + ' invisible character(s) from ' + what)
  return answer.ok ? null : answer.failure
}

// ---------------------------------------------------------------------------
// MCP findings: hidden text the MCP guard stripped from a server's
// descriptions, schemas or instructions. Those are read before any session
// exists, so the guard keeps each finding under the server's configuration
// hash, and a finding raises the untrusted leg of exactly the sessions that
// enumerate that server: whose request lists its tools or instructions, or
// that call one of its tools. Every other session on the instance is left
// alone.
// ---------------------------------------------------------------------------

// (root, configuration hash) pairs already raised, so a finding costs one
// request per lineage. Legs only rise, so a repeat would change nothing.
const appliedFindings = new Set<string>()

async function applyMcpFindings(ctx: PluginContext, session: string, findings: readonly McpFinding[]): Promise<Failure | null> {
  for (const finding of findings) {
    const key = (await rootOf(ctx, session)) + '|' + finding.hash
    if (appliedFindings.has(key)) continue
    const answer = await observe(ctx, session, 'mcp', finding.reason)
    if (!answer.ok) return answer.failure
    appliedFindings.add(key)
    if (appliedFindings.size > MAX_TRACKED_SESSIONS) appliedFindings.delete(appliedFindings.values().next().value as string)
  }
  return null
}

// session.context, after the MCP guard's own context hook: the findings for
// the servers this request enumerates. A finding the monitor could not record
// stops the request, because its session would otherwise read the server's
// tools with its untrusted leg down.
async function mcpFindingsContext(ctx: PluginContext, e: SessionRequestEvent): Promise<void> {
  if (mcpGuard === null) return
  let failure: Failure | null
  try {
    failure = await applyMcpFindings(ctx, e.sessionID, mcpGuard.findingsFor(e as SessionContextLike))
  } catch (error) {
    throw new Error('barmkin-opencode: the model request was not sent (the MCP finding check failed: ' + errorText(error) + ')')
  }
  if (failure) throw new Error('barmkin-opencode: the model request was not sent, because ' + describeFailure(failure) + '. It lists an MCP server whose text hid invisible characters.')
}

// ---------------------------------------------------------------------------
// The egress gate. The normaliser re-keys 2.x calls to the names the shared
// egress classes match on, plus the Code Mode class (`execute` has an
// unmediated `fetch`, V25). The monitor decides on the class ids.
// ---------------------------------------------------------------------------

function deny(classIds: string[], message: string): EgressVerdict {
  return { kind: 'deny', classIds, rule: 'untrusted', message }
}

// Marks leg B when a call names a secret-bearing path. Returns the failure if
// the monitor could not record it, so the caller denies the call.
async function noteSensitiveAccess(ctx: PluginContext, session: string, calls: readonly EgressCall[]): Promise<Failure | null> {
  const call = calls.find(touchesSecretPath)
  if (!call) return null
  const answer = await observe(ctx, session, 'credential', 'a ' + call.tool + ' call named a credential path')
  return answer.ok ? null : answer.failure
}

// The egress gate for one tool call: notes any sensitive access in it,
// classifies it against the egress classes and asks the monitor for the
// verdict. A deny or warn is recorded for the status surface. Never answers
// allow, and any failure to reach the monitor denies. Every call asks, egress
// class or not, so a session the monitor does not know runs no tool at all.
async function egressGate(ctx: PluginContext, session: string, calls: readonly EgressCall[]): Promise<EgressVerdict> {
  const unrecorded = await noteSensitiveAccess(ctx, session, calls)
  if (unrecorded) return deny([], failureText('this call', unrecorded))
  const classes = classifyCalls(calls)
  const answer = await sessionRequest(ctx, session, 'decide', { classes: classes.map((c) => c.id as Class) })
  if (!answer.ok) return deny(classes.map((c) => c.id), failureText('this call', answer.failure))
  const root = await rootOf(ctx, session)
  const verdict = describeVerdict(answer.value, classes, shownLegs(root, answer.value.legs))
  if (verdict.kind !== 'pass') {
    viewOf(root).lastEgress = {
      tool: calls[0]?.tool ?? '',
      classIds: verdict.classIds,
      decision: verdict.kind,
      rule: verdict.kind === 'deny' ? verdict.rule : answer.value.rule,
      at: Date.now(),
    }
  }
  return verdict
}

const SHELL_TOOL_IDS = new Set(['shell', 'bash'])
const SUBAGENT_TOOL_IDS = new Set(['subagent', 'task'])
const CODE_MODE_TOOL_IDS = new Set(['execute'])
const WEB_TOOL_IDS = new Set(['webfetch', 'websearch'])
// Tool ids OpenCode 2.0 registers itself; used only when the tool list cannot be read.
const BUILTIN_TOOL_IDS = new Set([
  'shell', 'bash', 'read', 'write', 'edit', 'patch', 'apply_patch', 'glob', 'grep', 'list', 'webfetch', 'websearch',
  'subagent', 'task', 'skill', 'execute', 'todowrite', 'todoread', 'question', 'plan', 'lsp',
])

interface ToolMeta {
  // The MCP server namespace, when the tool is an MCP tool.
  mcpServer: string | null
  // Whether its result is untrusted content to screen.
  screened: boolean
}

const toolNamespaces = new Map<string, string | null>()
let toolListFresh = 0

async function refreshToolList(ctx: PluginContext): Promise<boolean> {
  try {
    const tools = await bounded('the tool list', () => ctx.tool.list())
    toolNamespaces.clear()
    for (const tool of tools) toolNamespaces.set(tool.id, tool.options?.namespace ?? null)
    toolListFresh = Date.now()
    return true
  } catch {
    return false
  }
}

// MCP tools register with a server namespace (tool/mcp.ts). A tool the list does
// not know is read as MCP unless it is one of OpenCode's own, so a failed lookup
// screens more rather than less.
async function toolMeta(ctx: PluginContext, toolId: string): Promise<ToolMeta> {
  if (!toolNamespaces.has(toolId) && Date.now() - toolListFresh > 2_000) await refreshToolList(ctx)
  const namespace = toolNamespaces.get(toolId) ?? mcpGuard?.serverOf(toolId)
  if (namespace) return { mcpServer: namespace, screened: true }
  if (namespace === undefined && !BUILTIN_TOOL_IDS.has(toolId)) return { mcpServer: null, screened: true }
  return { mcpServer: null, screened: false }
}

// How the normaliser tells an MCP tool from a built-in: the registry namespace the
// tool list reports, else (for an id the list does not know) anything that is not
// one of OpenCode's own. Mirrors toolMeta without refreshing the list.
function normaliseOptions(): NormaliseOptions {
  return {
    mcpServers: [...new Set([...toolNamespaces.values()].filter((v): v is string => typeof v === 'string' && v !== ''))],
    isMcpTool: (id) => {
      const namespace = toolNamespaces.get(id)
      return namespace ? true : namespace === undefined && !BUILTIN_TOOL_IDS.has(id)
    },
  }
}

// Skill loads are decided one at a time, so two loads dispatched together
// cannot both be decided before the first raises the untrusted leg.
let skillLoads: Promise<unknown> = Promise.resolve()

function serializeSkillLoad<T>(load: () => Promise<T>): Promise<T> {
  const run = skillLoads.then(load)
  skillLoads = run.catch(() => {})
  return run
}

// Decides one skill load and, when it may run, raises the untrusted leg before
// it does, so a failed or denied load still leaves the session tainted. Returns
// the deny text, or null when the load may run.
async function decideSkillLoad(ctx: PluginContext, session: string, id: string): Promise<string | null> {
  const answer = await sessionRequest(ctx, session, 'decide', { classes: ['skill-load'] })
  if (!answer.ok) return failureText('loading this skill', answer.failure)
  const root = await rootOf(ctx, session)
  if (answer.value.verdict === 'deny') {
    viewOf(root).lastEgress = { tool: 'skill', classIds: ['skill-load'], decision: 'deny', rule: answer.value.rule, at: Date.now() }
    const legs = shownLegs(root, answer.value.legs)
    return 'barmkin-opencode: loading a skill is blocked while this session is handling untrusted content (' + (legs.untrustedReason ?? SOURCE_TEXT[legs.untrusted]) + '). ' + STICKY_HINT
  }
  const raised = await observe(ctx, session, 'skill', 'skill "' + id + '" was loaded')
  return raised.ok ? null : failureText('loading this skill', raised.failure)
}

// The same advice ends every deny the shim writes itself: the taint never
// clears in this session.
const STICKY_HINT =
  'The taint is sticky: it holds for the rest of this session, and only a new session starts clean. Ask the user to run the command themselves, or to start a new session for this work.'

// Skill loads decided at execute.before and not yet rechecked at evaluate, per
// session. The load raised the untrusted leg itself, so the recheck must not
// deny it for the taint it carries; a skill action evaluate sees with no load
// pending (a later plugin renamed another tool into `skill`) is decided there.
// A load's entry goes when its after hook runs, so none outlives its load.
const skillLoadsPending = new Map<string, number>()

function skillId(input: unknown): string {
  const id = asRecord(input).id ?? asRecord(input).skill
  return typeof id === 'string' && id !== '' ? id : 'unnamed'
}

// ---------------------------------------------------------------------------
// The untrusted-content screen. The monitor scores and decides; the shim sends
// it the redacted windows and its local scores, and applies the decision.
// ---------------------------------------------------------------------------

type ScreenResult = { decision: 'pass' | 'escalate' } | { decision: 'deny'; withholdReason: string }

function describeScores(scores: Scores): string {
  return 'injection ' + scores.injection.toFixed(2) + ', credentials ' + scores.credentials.toFixed(2) + ', exfiltration ' + scores.exfiltration.toFixed(2)
}

// Screens one piece of untrusted content (a fetched page, an MCP result, a
// file read from outside the project, a subagent's result, a Code Mode
// result, a skill body). A deny withholds the content. A monitor that cannot
// screen it also withholds it: unscreened untrusted content never reaches the
// model.
async function screenContent(ctx: PluginContext, session: string, raw: string, source: Source, label: string, callId: string): Promise<ScreenResult> {
  if (exceedsScreenedLimit(raw)) return { decision: 'deny', withholdReason: SCREENED_LIMIT_REASON }
  const scrubbed = scrubInvisible(raw).text
  const scores: Scores = {
    injection: heuristicInjectionScore(scrubbed),
    credentials: containsSecretInEitherView(raw, REDACTION_RULES) ? 0.9 : 0,
    exfiltration: 0,
  }
  const input = classifierInput(raw, REDACTION_RULES, redactionCounters)
  if (input === null) return { decision: 'deny', withholdReason: 'its redacted text could not be cut into screen windows' }
  if (input.length === 0) return { decision: 'pass' }
  const plan = planWindows(input)
  const windows = plan.windows.map((w) => input.slice(w.start, w.end))

  const answer = await sessionRequest(ctx, session, 'screen', { source, windows, scores })
  if (!answer.ok) return { decision: 'deny', withholdReason: 'it could not be screened: ' + describeFailure(answer.failure) }
  const screened = answer.value
  const root = await rootOf(ctx, session)

  // Text past the last window was never sent, so the screen could not vouch
  // for it: the content raises the untrusted leg whatever the windows scored.
  let decision = screened.decision
  if (plan.covered < input.length && decision === 'pass') {
    const raised = await observe(ctx, session, source, label + ' ran past the screened windows')
    if (!raised.ok) return { decision: 'deny', withholdReason: 'it could not be screened: ' + describeFailure(raised.failure) }
    decision = 'escalate'
  }

  viewOf(root).lastScreen = { callId, label, decision, scores: screened.scores, gap: screened.gap, at: Date.now() }
  if (decision !== 'pass') noteReason(root, 'untrusted', label + ' (' + describeScores(screened.scores) + ')')
  if (screened.legs.sensitive !== 'none') noteReason(root, 'sensitive', label + ' scored on the credential question')
  if (decision === 'deny') return { decision, withholdReason: 'the screen flagged it (' + describeScores(screened.scores) + ')' }
  return { decision }
}

// What a withheld untrusted result tells the model. A withhold for size alone is
// not a danger, so it points to paging; any other reason sends the model back to
// the person.
function withheldMessage(what: string, reason: string): string {
  return 'barmkin-opencode: withheld ' + what + ' (' + reason + '). ' + (reason === SCREENED_LIMIT_REASON ? PAGING_ADVICE : 'Ask the user before retrying.')
}

// ---------------------------------------------------------------------------
// tool.execute.before: the early refusal. Every deny is a throw.
// ---------------------------------------------------------------------------

// Calls awaiting their after hook: a warn to append, and shell calls in flight
// by session (shell.create.before carries no session, so it reads these).
const pendingWarnings = new Map<string, string>()
const shellInFlight = new Map<string, string>()

// A refusal this file decided on, as opposed to a bug in the guard itself: it is
// rethrown as is, where anything else becomes a fail-closed refusal.
class GuardDeny extends Error {}

function guardFailure(what: string, error: unknown): Error {
  return new Error('barmkin-opencode: the ' + what + ' failed (' + errorText(error) + '), so this call was not run')
}

async function toolBefore(ctx: PluginContext, e: ToolBeforeEvent): Promise<void> {
  try {
    const meta = await toolMeta(ctx, e.tool)

    if (meta.mcpServer !== null) {
      // MCP server allowlist.
      if (!isServerAllowed(meta.mcpServer, parseAllowlist(pluginOptions.mcp_server_allowlist))) {
        throw new GuardDeny('barmkin-opencode: MCP server "' + meta.mcpServer + '" is not on the allowlist')
      }
      // A session that calls a server's tool enumerates it.
      const finding = mcpGuard?.findingFor(meta.mcpServer)
      const unrecorded = finding ? await applyMcpFindings(ctx, e.sessionID, [finding]) : null
      if (unrecorded) throw new GuardDeny(failureText('this MCP call', unrecorded))
    }

    // Subagent spawn gate.
    if (SUBAGENT_TOOL_IDS.has(e.tool)) {
      const answer = await sessionRequest(ctx, e.sessionID, 'status', {})
      if (!answer.ok) throw new GuardDeny(failureText('this subagent spawn', answer.failure))
      if (answer.value.legs.untrusted !== 'none') {
        const legs = shownLegs(await rootOf(ctx, e.sessionID), answer.value.legs)
        throw new GuardDeny('barmkin-opencode: subagent spawn blocked while this session is tainted (' + (legs.untrustedReason ?? SOURCE_TEXT[legs.untrusted]) + '). ' + STICKY_HINT)
      }
    }

    // Skill-tool taint gate: a loaded skill is untrusted content in its own
    // right, so the load is decided on its own and raises the leg before it runs.
    if (e.tool === 'skill') {
      const denied = await serializeSkillLoad(() => decideSkillLoad(ctx, e.sessionID, skillId(e.input)))
      if (denied) throw new GuardDeny(denied)
      track(skillLoadsPending, e.sessionID, (skillLoadsPending.get(e.sessionID) ?? 0) + 1, MAX_TRACKED_SESSIONS)
      return
    }

    // Egress gate over the call as the model proposed it. The final command, URL
    // or path is rechecked at permission time.
    const verdict = await egressGate(ctx, e.sessionID, normaliseEgressCalls(e.tool, e.input, normaliseOptions()))
    if (verdict.kind === 'deny') throw new GuardDeny(verdict.message)
    if (verdict.kind === 'warn') track(pendingWarnings, e.id, verdict.message)
    if (SHELL_TOOL_IDS.has(e.tool)) track(shellInFlight, e.id, e.sessionID)
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw guardFailure('egress guard', error)
  }
}

// ---------------------------------------------------------------------------
// permission.evaluate: the final recheck, against the final command, URL or path
// after every other plugin's rewrite (V5-V9), with the call's own session.
// Deny = throw, never `effect = "deny"`.
// ---------------------------------------------------------------------------

async function permissionEvaluate(ctx: PluginContext, e: PermissionEvaluation): Promise<void> {
  try {
    const calls = normaliseEvaluate(e.action, e.resources, normaliseOptions())
    const skillCalls = calls.filter((c) => c.tool === 'Skill')
    const pending = skillLoadsPending.get(e.sessionID) ?? 0
    if (skillCalls.length > 0) {
      if (pending > 0) {
        if (pending === 1) skillLoadsPending.delete(e.sessionID)
        else skillLoadsPending.set(e.sessionID, pending - 1)
      } else {
        for (const call of skillCalls) {
          const denied = await serializeSkillLoad(() => decideSkillLoad(ctx, e.sessionID, skillId(call.input)))
          if (denied) throw new GuardDeny(denied)
        }
      }
    }
    // The final action and resources after every other plugin's rewrite. An
    // action with no resources the normaliser can read (Code Mode `execute`, an
    // MCP tool) classifies on its name alone.
    const verdict = await egressGate(ctx, e.sessionID, calls.filter((c) => c.tool !== 'Skill'))
    if (verdict.kind === 'deny') throw new GuardDeny(verdict.message)
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw new Error('barmkin-opencode: the permission-time egress guard failed (' + errorText(error) + '), so this call was not run')
  }
}

// ---------------------------------------------------------------------------
// shell.create.before: the shell layer, after every tool hook. The event carries
// no session, so the command is checked against every session with a shell tool
// call in flight, and it is denied only when every one of them would deny it
// (captain call C5). Where any of them would let it run, the shell layer leaves
// it to permission.evaluate, which rechecks the same command with the call's own
// session. A shell no tool call started (a person's own `!` command) is left
// alone. This layer only asks: it raises no leg, because it cannot tell whose
// command this is.
// ---------------------------------------------------------------------------

async function shellCreateBefore(ctx: PluginContext, e: ShellCreateBefore): Promise<void> {
  const sessions = [...new Set(shellInFlight.values())]
  if (sessions.length === 0) return
  try {
    const classes = classifyCalls(normaliseEgressCalls('shell', { command: e.command }))
    const ids = classes.map((c) => c.id as Class)
    const roots = new Map<string, string>()
    for (const session of sessions) roots.set(await rootOf(ctx, session), session)
    // The first session's reason is the one the deny gives.
    let denial: string | null = null
    for (const [root, session] of roots) {
      const answer = await sessionRequest(ctx, session, 'decide', { classes: ids })
      // A session whose verdict the monitor could not give would deny.
      if (!answer.ok) {
        denial ??= failureText('this command', answer.failure)
        continue
      }
      const verdict = describeVerdict(answer.value, classes, shownLegs(root, answer.value.legs))
      if (verdict.kind !== 'deny') return
      denial ??= verdict.message
    }
    throw new GuardDeny(denial ?? 'barmkin-opencode: this command is denied in every session that could have started it.')
  } catch (error) {
    if (error instanceof GuardDeny) throw error
    throw new Error('barmkin-opencode: the shell guard failed (' + errorText(error) + '), so this command was not run')
  }
}

// ---------------------------------------------------------------------------
// tool.execute.after: screens, then redaction last, so redaction sees whatever an
// earlier step added. Fires on errors too (V21). A throw here reports an error
// after the command already ran (V22), so a failure first tries to withhold.
// ---------------------------------------------------------------------------

// Withholds an after event's result, or throws when the event cannot be edited
// (a frozen error message): a result the guard could not replace must not be
// delivered, and a throw after the tool ran reaches the model as an error (V22).
function withhold(e: ToolAfterEvent, message: string): void {
  if (!withholdAfterEvent(e, message)) throw new Error('barmkin-opencode: the result could not be withheld')
}

async function toolAfter(ctx: PluginContext, e: ToolAfterEvent): Promise<void> {
  shellInFlight.delete(e.id)
  if (e.tool === 'skill') skillLoadsPending.delete(e.sessionID)
  const warning = pendingWarnings.get(e.id)
  pendingWarnings.delete(e.id)
  try {
    const meta = await toolMeta(ctx, e.tool)
    const payload = e.status === 'completed' ? e.result : e.error

    const withheld = await screenAfterResult(ctx, e, meta)
    if (withheld) return
    if (warning !== undefined && e.status === 'completed') noticeAfterEvent(e, warning)

    // Over the budget: a result nothing can scan whole is withheld, with the
    // limits of an untrusted surface where a screen covers the tool.
    const size = measureResult(payload, meta.screened)
    if (size !== 'within') {
      withhold(e, 'barmkin-opencode: this tool result is larger than the redaction scan budget, so it was withheld. ' + PAGING_ADVICE)
      return
    }

    let hiddenCount = 0
    let redactionHits = 0
    const redactValue = (value: string): string => {
      const scrubbed = scrubInvisible(value)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(value)
      redactionHits += redactedCount
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return value
      return redacted
    }
    redactAfterEvent(e, redactValue)

    // A redaction hit means a credential-shaped value just passed through this
    // session: leg B of the trifecta. Raised before the result is delivered, so
    // the very next egress call sees it. A leg the monitor could not record
    // withholds the result, as does an invisible-text payload it could not record.
    if (redactionHits > 0) {
      const raised = await observe(ctx, e.sessionID, 'credential', 'a ' + (meta.mcpServer ? 'tool' : e.tool) + ' result held a credential-shaped value')
      if (!raised.ok) {
        withhold(e, failureText('this result', raised.failure) + ' It held a credential-shaped value.')
        return
      }
    }
    const unrecorded = await taintForScrub(ctx, e.sessionID, hiddenCount, 'tool:' + (meta.mcpServer ? 'mcp' : e.tool))
    if (unrecorded) withhold(e, failureText('this result', unrecorded) + ' It hid invisible characters.')
  } catch (error) {
    try {
      withhold(e, 'barmkin-opencode: the result guard failed (' + errorText(error) + '); the result was withheld to avoid leaking an unredacted secret or untrusted content')
    } catch {
      throw new Error('barmkin-opencode: the result guard failed, so the result was not delivered')
    }
  }
}

// Whether the tool's result is untrusted content, and so is screened: its
// monitor source and its label.
function screenTargetFor(toolId: string, meta: ToolMeta, input: unknown): { source: Source; label: string } | null {
  if (meta.mcpServer !== null) return { source: 'mcp', label: 'mcp:' + meta.mcpServer }
  if (meta.screened) return { source: 'mcp', label: 'mcp:' + toolId }
  if (WEB_TOOL_IDS.has(toolId)) return { source: 'fetch', label: 'fetch:' + toolId }
  if (SUBAGENT_TOOL_IDS.has(toolId)) return { source: 'peer', label: 'subagent' }
  if (CODE_MODE_TOOL_IDS.has(toolId)) return { source: 'fetch', label: 'codemode' }
  if (toolId === 'read') {
    const path = asRecord(input).path
    return typeof path === 'string' && isOutsideCwd(path, projectDirectory) ? { source: 'read', label: 'read:' + path } : null
  }
  return null
}

// Screens a completed or error result and a skill body. Returns true when the result was
// withheld, in which case nothing else is done to it.
async function screenAfterResult(ctx: PluginContext, e: ToolAfterEvent, meta: ToolMeta): Promise<boolean> {
  if (e.tool === 'skill') {
    const text = afterEventText(e)
    if (!text) return false
    const unrecorded = await taintForScrub(ctx, e.sessionID, scrubInvisible(text).hiddenCount, 'a skill body')
    if (unrecorded) {
      withhold(e, skillBodyWithheldText(describeFailure(unrecorded)))
      return true
    }
    const verdict = await screenContent(ctx, e.sessionID, text, 'skill', 'skill:' + skillId(e.input), e.id)
    if (verdict.decision === 'deny') {
      withhold(e, skillBodyWithheldText(verdict.withholdReason))
      return true
    }
    if (verdict.decision === 'escalate') noticeAfterEvent(e, UNTRUSTED_CONTENT_WARNING)
    return false
  }

  const target = screenTargetFor(e.tool, meta, e.input)
  if (target === null) return false
  const text = afterEventText(e)
  if (!text) return false
  const verdict = await screenContent(ctx, e.sessionID, text, target.source, target.label, e.id)
  if (verdict.decision === 'deny') {
    withhold(e, withheldMessage('this result', verdict.withholdReason))
    return true
  }
  if (verdict.decision === 'escalate') noticeAfterEvent(e, UNTRUSTED_CONTENT_WARNING)
  return false
}

// ---------------------------------------------------------------------------
// session.prompt: redact what the person pasted. Refusing the turn is a throw
// (V26). No prompt lowers the taint.
// ---------------------------------------------------------------------------

function sessionPrompt(e: SessionPromptEvent): void {
  const text = promptText(e as SessionPromptShape)
  if (exceedsScreenedLimit(text)) {
    throw new Error('barmkin-opencode: your message is longer than the 16 KiB scan limit, so it was withheld')
  }
  let redactedCount = 0
  let withheld = false
  mapPromptStrings(e as SessionPromptShape, (value) => {
    const result = redactInEitherView(value, {})
    redactedCount += result.redactedCount
    if (result.text === WITHHELD_TEXT) withheld = true
    return result.redactedCount === 0 ? value : result.text
  })
  if (withheld) throw new Error('barmkin-opencode: your message could not be fully scanned after redaction, so it was withheld')
  if (redactedCount > 0) debugLog('barmkin-opencode: redacted ' + redactedCount + ' likely secret(s) from your message before sending it')
}

// ---------------------------------------------------------------------------
// The model boundary: session.context (before each primary request), title,
// compaction and generate. The raw copy of a prompt-borne or background-shell
// secret is removed from every request, side calls included (V28, V30). Skill
// listings are neutralised here too (V23, V31).
// ---------------------------------------------------------------------------

// The skill listing renders `<skill><id>..</id><name>..</name><description>..</description></skill>`
// (core skill/instructions.ts). Each entry goes through the lib's `- name: description`
// neutraliser alone, so an entry cannot reach into its neighbour.
const SKILL_ENTRY = /<skill>\s*<id>([\s\S]*?)<\/id>\s*<name>([\s\S]*?)<\/name>\s*<description>([\s\S]*?)<\/description>\s*<\/skill>/g

function neutralizeSkillListingXml(text: string): string {
  if (!text.includes('<skill>')) return text
  return text.replace(SKILL_ENTRY, (entry: string, id: string, name: string, description: string) => {
    const { text: neutralised, withheld } = neutralizeSkillListing('- ' + name + ': ' + scrubInvisible(description).text)
    if (withheld > 0) return ''
    const prefix = '- ' + name + ': '
    if (!neutralised.startsWith(prefix)) return ''
    const cleaned = neutralised.slice(prefix.length)
    return cleaned === description ? entry : '<skill><id>' + id + '</id><name>' + name + '</name><description>' + cleaned + '</description></skill>'
  })
}

// A rewriter for one request, and the most invisible-text carriers it
// stripped from any one string.
function boundaryRewriter(): { rewrite: (value: string) => string; hidden: () => number } {
  const counters: Record<string, number> = {}
  let most = 0
  return {
    rewrite: (value) => {
      const scrubbed = scrubInvisible(value)
      most = Math.max(most, scrubbed.hiddenCount)
      const { text, redactedCount } = redactInEitherView(value, counters)
      const redacted = redactedCount === 0 && scrubbed.strippedCount === 0 ? value : text
      return neutralizeSkillListingXml(redacted)
    },
    hidden: () => most,
  }
}

async function modelBoundary(ctx: PluginContext, surface: 'context' | 'compaction' | 'generate' | 'title', e: SessionRequestEvent): Promise<void> {
  // A session registers at its first primary request, the counterpart of
  // Claude Code's session start. A failure is retried by the first call that
  // needs the session, which then denies if the monitor still cannot answer.
  if (surface === 'context' && TOKEN.test(e.sessionID) && !registered.has(e.sessionID)) {
    try {
      const answer = await registerSession(ctx, e.sessionID)
      if (!answer.ok) debugLog('barmkin-opencode: session ' + e.sessionID + ' is not registered: ' + describeFailure(answer.failure))
    } catch (error) {
      debugLog('barmkin-opencode: session ' + e.sessionID + ' could not be registered: ' + errorText(error))
    }
  }
  const { rewrite, hidden } = boundaryRewriter()
  mapRequestStrings(e as SessionContextShape, rewrite)
  if (surface !== 'title') {
    // Tool descriptions are the model's too; a result an earlier plugin set on a
    // compaction enters history without passing the context hook.
    mapToolDescriptions((e as SessionContextShape).tools, rewrite, false)
    if (surface === 'compaction') mapCompactionResult(e as SessionCompactionShape, rewrite)
  }
  let unrecorded: Failure | null
  try {
    unrecorded = await taintForScrub(ctx, e.sessionID, hidden(), 'the model request')
  } catch (error) {
    throw new Error('barmkin-opencode: the ' + surface + ' request was not sent (' + errorText(error) + ')')
  }
  if (unrecorded) throw new Error('barmkin-opencode: the ' + surface + ' request was not sent, because ' + describeFailure(unrecorded) + '. It hid invisible characters.')
}

// ---------------------------------------------------------------------------
// The status channel and the posture line.
// ---------------------------------------------------------------------------

export interface Seat {
  inventory: 'ok' | 'unavailable'
  // The seat this guard runs from, as far as the inventory and environment show.
  name: 'inline-config' | 'file-or-package' | 'unverified'
  inlineSeated: boolean
  projectConfigDisabled: boolean
  others: string[]
  failed: string[]
}

// What the posture line says about the monitor, from the configuration and a
// health check made after setup: how OpenCode reports its posture, and whether
// the monitor answered.
export interface MonitorPosture {
  sandboxed: boolean
  socketConfigured: boolean
  // 'unchecked' until the health check answers.
  health: 'ok' | 'degraded' | 'unchecked' | Failure
}

let seat: Seat = { inventory: 'unavailable', name: 'unverified', inlineSeated: false, projectConfigDisabled: false, others: [], failed: [] }
let monitorPosture: MonitorPosture = { sandboxed: false, socketConfigured: false, health: 'unchecked' }
let postureLines: string[] = []

function envFlag(name: string): boolean {
  const value = process.env[name]
  return value === '1' || value === 'true'
}

// The plugin-inventory probe (re-scout section 4: seat detection comes from the
// inventory, not from guessing). `plugin.list()` returns every plugin entry with
// its source and state; the environment says whether this guard is the inline-config
// plugin and whether project config is off.
async function probeSeat(ctx: PluginContext): Promise<Seat> {
  const projectConfigDisabled = envFlag('OPENCODE_DISABLE_PROJECT_CONFIG')
  const inlineConfig = process.env.OPENCODE_CONFIG_CONTENT ?? ''
  try {
    let timer: ReturnType<typeof setTimeout> | undefined
    const listed = await Promise.race([
      ctx.plugin.list(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), INVENTORY_TIMEOUT_MS)
      }),
    ]).finally(() => clearTimeout(timer))
    const raw = unwrap(listed)
    const entries = (Array.isArray(raw) ? raw : []) as PluginInfo[]
    const own = entries.find((p) => p.id === PLUGIN_ID)
    const ownTarget = own?.source.path ?? own?.source.target
    const inlineSeated =
      inlineConfig !== '' && (inlineConfig.includes(PLUGIN_ID) || (ownTarget !== undefined && inlineConfig.includes(ownTarget)))
    const nameOf = (p: PluginInfo): string => p.id ?? p.source.path ?? p.source.target ?? '(unnamed)'
    const others = entries.filter((p) => p !== own && p.source.type !== 'builtin').map(nameOf)
    const failed = entries.filter((p) => p.state.status === 'failed').map(nameOf)
    return { inventory: 'ok', name: inlineSeated ? 'inline-config' : 'file-or-package', inlineSeated, projectConfigDisabled, others, failed }
  } catch {
    return {
      inventory: 'unavailable',
      name: 'unverified',
      inlineSeated: inlineConfig.includes(PLUGIN_ID),
      projectConfigDisabled,
      others: [],
      failed: [],
    }
  }
}

// Asks the monitor whether it is up, without a session.
async function probeMonitor(): Promise<MonitorPosture> {
  const socketConfigured = socketPath() !== ''
  const sandboxed = reportedPosture().sandbox_enabled
  if (!socketConfigured) return { sandboxed, socketConfigured, health: 'not_configured' }
  const answer = await postMonitor(socketPath(), 'health', { version: VERSION })
  return { sandboxed, socketConfigured, health: answer.ok ? answer.value.state : answer.failure }
}

// The per-seat gaps for the posture line's `not covered:` clause.
function notCovered(s: Seat): string[] {
  const gaps = [
    'secrets already in stored transcripts and shell output files',
    'MCP tool arguments, Code Mode fetch and command-template shell',
    'any session where this guard is not loaded',
  ]
  if (!mcpDescriptionGuard) gaps.push('MCP tool descriptions')
  if (s.others.length > 0) gaps.push('plugins loaded beside this guard')
  return gaps
}

// The posture line is shipping text (CONTRACT.md "Posture line"): the first line
// is verbatim, the conditional lines are the re-scout section 2.2 wording, one per
// condition, plus one per reason the monitor will deny every guarded call. The
// seat is named inside `not covered:`.
export function buildPostureLines(s: Seat, m: MonitorPosture = monitorPosture, coreSha: string = CORE_SHA): string[] {
  const seatText = s.name === 'inline-config' ? 'seat "inline-config" is user-owned, not administrator-enforced' : s.name === 'file-or-package' ? 'seat "file-or-package" is user-owned, not administrator-enforced' : 'seat unverified'
  const lines = [
    '\u{1F3F0} barmkin-opencode ' +
      PLUGIN_VERSION +
      ' (core ' +
      coreSha +
      ') · partial port, not equivalent to barmkin-mod for Claude Code · OpenCode 2 has no administrator-locked plugin seat · not covered: ' +
      [seatText, ...notCovered(s)].join('; '),
  ]
  if (!s.inlineSeated && !s.projectConfigDisabled) {
    lines.push(
      "\u{1F3F0} barmkin-opencode: a repository's opencode.json can unload this guard unless project config is disabled or the guard is seated through OPENCODE_CONFIG_CONTENT.",
    )
  }
  if (s.others.length > 0 && !s.inlineSeated) {
    lines.push(
      '\u{1F3F0} barmkin-opencode: a later plugin can re-insert what the guard redacted; the inline-config seat or a plugin allowlist closes this (loaded beside the guard: ' +
        s.others.join(', ') +
        ').',
    )
  }
  if (s.failed.length > 0) lines.push('\u{1F3F0} barmkin-opencode: plugin(s) failed to load: ' + s.failed.join(', ') + '.')
  if (s.inventory === 'unavailable') lines.push('\u{1F3F0} barmkin-opencode: the plugin inventory could not be read, so the seat is unverified.')
  if (!m.socketConfigured) {
    lines.push('\u{1F3F0} barmkin-opencode: ' + SOCKET_ENV + ' is not set, so every guarded tool call is denied.')
  } else if (m.health !== 'ok' && m.health !== 'unchecked') {
    lines.push('\u{1F3F0} barmkin-opencode: ' + (m.health === 'degraded' ? 'the barmkin monitor reports itself degraded' : describeFailure(m.health)) + ', so every guarded tool call is denied.')
  }
  if (!m.sandboxed) {
    lines.push(
      '\u{1F3F0} barmkin-opencode: OpenCode runs its tools outside a sandbox, so the barmkin monitor refuses its sessions and every guarded tool call is denied. Set the sandboxed option only when OpenCode runs inside an OS sandbox whose tools cannot reach the monitor socket.',
    )
  }
  return lines
}

// The server-to-TUI channel (re-scout V34-V36; src/status-rpc): the TUI module
// calls `status` with no session, so taint is reported across every root this
// process has seen: tainted when the monitor last reported any of them tainted.
function statusReport(): StatusReport {
  const roots = [...views.entries()]
  const taintedRoot = roots.find(([, v]) => v.legs.untrusted !== 'none')
  const sensitiveRoot = roots.find(([, v]) => v.legs.sensitive !== 'none')
  const reason = taintedRoot === undefined ? null : (taintedRoot[1].untrustedReason ?? SOURCE_TEXT[taintedRoot[1].legs.untrusted])
  return {
    version: PLUGIN_VERSION,
    postureLine: postureLines[0] ?? '',
    conditionalLines: postureLines.slice(1),
    seat: {
      kind: seat.name,
      label: seat.name === 'unverified' ? 'unverified' : seat.name === 'inline-config' ? 'inline config' : 'file or package',
      repoCanUnload: !seat.inlineSeated && !seat.projectConfigDisabled,
    },
    taint: {
      tainted: taintedRoot !== undefined,
      sensitive: sensitiveRoot !== undefined,
      ...(reason !== null ? { reason } : {}),
    },
    monitor: { state: monitorState },
    ...(mcpGuard !== null ? { mcp: mcpGuard.status() } : {}),
  }
}

async function installOptional(ctx: PluginContext): Promise<void> {
  try {
    const registration = (await ctx.rpc.register(statusRpc, { status: async () => statusReport() })) as {
      events?: { emit?: (name: 'changed', payload: { reason: string }) => Promise<void> }
    } | null
    const emit = registration?.events?.emit
    if (typeof emit === 'function') {
      emitChanged = (reason) => {
        emit.call(registration!.events, 'changed', { reason }).catch((error: unknown) => debugLog('barmkin-opencode: status event failed: ' + String(error)))
      }
    }
  } catch (error) {
    debugLog('barmkin-opencode: rpc registration failed: ' + String(error))
  }
}

// Emits the posture line once the inventory is readable and the monitor has
// answered its health check. Deferred: the inventory may wait on plugin
// activation, and setup must not wait on either.
function startPostureProbe(ctx: PluginContext): void {
  void Promise.all([probeSeat(ctx), probeMonitor()]).then(([probed, monitor]) => {
    seat = probed
    monitorPosture = monitor
    refreshMcpDescriptionGuard()
    postureLines = buildPostureLines(seat)
    for (const line of postureLines) console.error(line)
    emitChanged('seat')
  })
}

// ---------------------------------------------------------------------------
// The plugin.
// ---------------------------------------------------------------------------

export default {
  id: PLUGIN_ID,
  setup: async (ctx: PluginContext) => {
    pluginOptions = ctx.options ?? {}
    projectDirectory = ctx.location?.directory ?? ''
    monitorPosture = { sandboxed: reportedPosture().sandbox_enabled, socketConfigured: socketPath() !== '', health: 'unchecked' }
    postureLines = buildPostureLines(seat)

    // Guards. A registration that fails here throws out of setup, which OpenCode
    // reports as a failed plugin; nothing is half-registered silently.
    await ctx.tool.hook('execute.before', (e) => toolBefore(ctx, e))
    await ctx.permission.hook('evaluate', (e) => permissionEvaluate(ctx, e))
    await ctx.shell.hook('create.before', (e) => shellCreateBefore(ctx, e))
    await ctx.tool.hook('execute.after', (e) => toolAfter(ctx, e))
    await ctx.session.hook('prompt', (e) => sessionPrompt(e))
    await ctx.session.hook('context', (e) => modelBoundary(ctx, 'context', e))
    await ctx.session.hook('title', (e) => modelBoundary(ctx, 'title', e))
    await ctx.session.hook('compaction', (e) => modelBoundary(ctx, 'compaction', e))
    await ctx.session.hook('generate', (e) => modelBoundary(ctx, 'generate', e))

    // The MCP description neutraliser (src/mcp-guard). It registers its own
    // transforms and a second, allowlist-only before/evaluate/context hook, and it
    // never throws: a failed install shows in healthy() and leaves the posture line
    // naming MCP tool descriptions as not covered.
    mcpGuard = await installMcpGuard(ctx as unknown as McpGuardHost, {
      allowlist: ctx.options?.mcp_server_allowlist,
      hiddenTextThreshold: INVISIBLE_CHAR_TAINT_THRESHOLD,
    })
    // After the guard's own context hook, so the findings it makes on a request
    // apply to that request.
    await ctx.session.hook('context', (e) => mcpFindingsContext(ctx, e))
    refreshMcpDescriptionGuard()
    postureLines = buildPostureLines(seat)

    await installOptional(ctx)
    startPostureProbe(ctx)
  },
}
