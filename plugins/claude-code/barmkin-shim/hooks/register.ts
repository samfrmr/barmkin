// Barmkin shim for Claude Code: the session's guard, connected to the barmkin
// monitor. A port of barmkin-mod's hooks module (samfrmr/barmkin-mod
// hooks/register.ts) in which the monitor holds the session's taint.
//
// The monitor (internal/monitor, reached over HTTP on its Unix socket through
// the contract in lib/proto.ts) owns the session: its two legs (untrusted and
// sensitive), the egress decision over them, and the screen of untrusted
// content. Legs only rise. Nothing in the shim lowers one: no prompt,
// command, compaction or /clear clears the taint. Only root's opt-in
// administrative clear does (README, "Administrative clear").
//
// The shim keeps what needs the content, which never leaves it except as
// redacted screen windows: secret redaction and invisible-text scrub,
// classifying calls into egress class ids, the MCP and skill guards, the
// agent-to-agent firewall, the inline-shell tool.check line, the posture
// check, the HUD and the status command. Its $.state atoms are a read-through
// cache of the legs the monitor last reported, plus the local text of why each
// leg rose, for the HUD and the status command, which never wait on the monitor.
//
// It also pre-registers every tool call with the monitor from session.append,
// before the managed `barmkin gate` PreToolUse hook asks whether the call was
// pre-registered. So a session without this shim runs no tools at all.
//
// Fail-closed convention: a hook that guards (can deny, consume or withhold)
// gets a `.catch` that denies on failure, and every monitor request has its own
// deadline. A request that fails, times out or gets a malformed answer denies
// the step it guards: an unreachable or unknown monitor never lets a guarded
// call through. The advisory hooks (the HUD and the hint) have no catch and
// never call the monitor.
//
// `$` is only ever used as `$.namespace.method(...)` and only ever passed to a
// function declared at this file's top level (never into an imported file or a
// function nested inside a hook), per `claude plugin validate`'s static-analysis
// rules for the mods API.
//
// The root policy (/etc/barmkin/policy.yaml, lib/policy.ts) can only add to the
// built-in redaction rules, injection phrases, secret paths and outward-effect
// commands. It is read once per module load, from that path only. An invalid
// policy is never partly applied: every monitor request fails, so every step
// the monitor guards is denied, and local redaction keeps the built-in rules.
//
// Environment variables:
//   BARMKIN_MONITOR_SOCKET   monitor Unix socket path (required)
import { atom, read, update } from 'claude-code'
import {
  BUILTIN_POLICY,
  MAX_POLICY_BYTES,
  POLICY_PATH,
  describePolicy,
  policyFromRead,
  type ActivePolicy,
  type PolicyLoad,
  type PolicyRead,
} from './lib/policy'
import {
  redactInEitherView as redactInEitherViewLib,
  classifierInput,
  WITHHELD_TEXT,
  containsAnySecret,
  containsSecretInEitherView,
  measureResult,
  exceedsScanLimit,
  exceedsScreenedLimit,
  SCREENED_LIMIT_REASON,
  PAGING_ADVICE,
} from './lib/redaction'
import { scannedPrefix, prefixNotice } from './lib/scanned-prefix'
import { scrubInvisible } from './lib/scrub'
import { isOutsideCwd, heuristicInjectionScore, UNTRUSTED_CONTENT_WARNING } from './lib/taint'
import {
  classifyEgress,
  describeVerdict,
  touchesSecretPath,
  isInlineSkillShell,
  inlineShellDenyReason,
  SOURCE_TEXT,
  STICKY_HINT,
  type EgressCall,
  type EgressVerdict,
  type ShownLegs,
} from './lib/egress'
import { planWindows } from './lib/classifier-windows'
import { neutralizeDescription, parseMcpServerName, isAllowedServer } from './lib/mcp-guard'
import { extractResultText, appendContext, withholdResult } from './lib/tool-result'
import { meetsMinimumVersion, MIN_CLAUDE_CODE_VERSION } from './lib/version'
import { checkPosture, reportedPosture } from './lib/posture'
import { skillBodyWithheldText, skillListingWithheldText, neutralizeSkillListing } from './lib/skill-guard'
import {
  answerLegs,
  describeFailure,
  encodeBody,
  interpretReply,
  monitorUrl,
  REQUEST_DEADLINE_MS,
  TOKEN,
  type Answer,
  type Failure,
} from './lib/monitor.ts'
import { VERSION, type Class, type Legs, type Op, type Requests, type Scores, type Source } from './lib/proto.ts'

// ---------------------------------------------------------------------------
// $.state atoms. Declared values must match types/index.d.ts, and plugin/key
// must be string literals so `claude plugin validate` can read them.
// ---------------------------------------------------------------------------

interface ScreenRecord {
  toolUseId: string
  label: string
  decision: 'pass' | 'escalate' | 'deny'
  scores: Scores
  gap: 'none' | 'scan_limit' | 'unclassified'
  at: number
}

interface EgressRecord {
  tool: string
  classIds: string[]
  decision: 'deny' | 'warn'
  rule: string
  at: number
}

// The legs the monitor last reported for this session. A cache for the HUD and
// the status command only: every decision asks the monitor.
const untrustedLeg = atom({ plugin: 'barmkin-shim', key: 'untrustedLeg' }, 'none' as Source)
const sensitiveLeg = atom({ plugin: 'barmkin-shim', key: 'sensitiveLeg' }, 'none' as Source)
// Why each leg rose, as the shim saw it. The first reason recorded wins. The
// monitor never holds this text; it knows only the source.
const untrustedReason = atom({ plugin: 'barmkin-shim', key: 'untrustedReason' }, null as string | null)
const sensitiveReason = atom({ plugin: 'barmkin-shim', key: 'sensitiveReason' }, null as string | null)
// The last answer from the monitor: 'ok', or why the last request failed.
const monitorState = atom({ plugin: 'barmkin-shim', key: 'monitorState' }, 'ok' as string)
// The monitor's classifier state, as its last status answer reported it.
const classifierState = atom({ plugin: 'barmkin-shim', key: 'classifierState' }, 'degraded' as string)
// The first session id this process registered: the root of its lineage. A
// later session in the same process (after /clear, which starts a new session
// id) registers under it, so it shares the same legs.
const rootSession = atom({ plugin: 'barmkin-shim', key: 'rootSession' }, null as string | null)
const lastEgress = atom({ plugin: 'barmkin-shim', key: 'lastEgress' }, null as EgressRecord | null)
const lastScreen = atom({ plugin: 'barmkin-shim', key: 'lastScreen' }, null as ScreenRecord | null)

// Redaction placeholder counters. Not security state (no secret value is
// ever kept, only a per-category count for unique labels), so a plain
// module variable is fine; it resets on reload like any other.
const redactionCounters: Record<string, number> = {}

// More than this many invisible-text carriers (scrubInvisible's
// `hiddenCount`, which leaves out ANSI/C0 terminal formatting and the
// ZWNJ/ZWJ of ordinary Persian/Indic text and ZWJ emoji) stripped from one
// piece of content raise the untrusted leg: a payload smuggled one invisible
// code point per byte runs well past this.
const INVISIBLE_CHAR_TAINT_THRESHOLD = 32
// This plugin's own manifest name, as it appears before the `@marketplace`
// suffix in a managed prependPlugins entry (the session.start posture check).
const PLUGIN_NAME = 'barmkin-shim'
const HOST = 'claude_code'

let pluginOptions: Record<string, unknown> = {}

function parseAllowlist(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string' && v.length > 0)
  if (typeof raw === 'string' && raw.length > 0) {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return []
}

function redactInEitherView(text: string, policy: ActivePolicy): { text: string; redactedCount: number } {
  return redactInEitherViewLib(text, policy.redactionRules, redactionCounters)
}

// ---------------------------------------------------------------------------
// The root policy. Read once per module load from POLICY_PATH alone. $.fs
// reports no owner or mode, so the shim checks what it can see: the path is
// not a symbolic link, resolves to itself (no linked directory above it), and
// is a regular file within the size bound. Root's ownership of /etc, and
// AppArmor keeping a sandbox's root out of it, are the deployment's.
// ---------------------------------------------------------------------------

let policyLoad: Promise<PolicyLoad> | null = null

function currentPolicy($: any): Promise<PolicyLoad> {
  if (!policyLoad) policyLoad = readPolicyFile($).then(policyFromRead, () => policyFromRead({ kind: 'refused', reason: 'it could not be read' }))
  return policyLoad
}

// The lists every local check uses. An invalid policy adds nothing here;
// postMonitor fails every request under it, so the guarded steps deny.
async function enforcedPolicy($: any): Promise<ActivePolicy> {
  const load = await currentPolicy($)
  return load.state === 'invalid' ? BUILTIN_POLICY : load.policy
}

async function readPolicyFile($: any): Promise<PolicyRead> {
  let stat: any
  try {
    stat = await $.fs.stat(POLICY_PATH, { resolve: true })
  } catch {
    let exists = true
    try {
      exists = await $.fs.exists(POLICY_PATH)
    } catch {
      // treated as present and unreadable below
    }
    return exists ? { kind: 'refused', reason: 'it could not be read' } : { kind: 'absent' }
  }
  if (stat?.isLink) return { kind: 'refused', reason: 'it is a symbolic link' }
  if (stat?.realPath !== POLICY_PATH) return { kind: 'refused', reason: 'its path does not resolve to ' + POLICY_PATH }
  if (stat.kind !== 'file') return { kind: 'refused', reason: 'it is not a regular file' }
  if (typeof stat.size !== 'number' || stat.size > MAX_POLICY_BYTES) return { kind: 'refused', reason: 'it is larger than ' + MAX_POLICY_BYTES + ' bytes' }
  let text: unknown
  try {
    text = await $.fs.read(POLICY_PATH)
  } catch {
    return { kind: 'refused', reason: 'it could not be read' }
  }
  return typeof text === 'string' ? { kind: 'file', text } : { kind: 'refused', reason: 'it could not be read as text' }
}

// ---------------------------------------------------------------------------
// The monitor. Each request is one POST over the socket, raced against its own
// deadline. `$.http.fetch` takes no abort signal, so a late answer is dropped.
// ---------------------------------------------------------------------------

async function postMonitor<O extends Op>($: any, op: O, request: Requests[O]): Promise<Answer<O>> {
  if ((await currentPolicy($)).state === 'invalid') return { ok: false, failure: 'policy_invalid' }
  const socketPath = await $.env.get('BARMKIN_MONITOR_SOCKET')
  if (typeof socketPath !== 'string' || socketPath === '') return { ok: false, failure: 'not_configured' }
  const body = encodeBody(op, request)
  if (body === null) return { ok: false, failure: 'bad_request' }

  let timer: { cancel: () => void } | null = null
  const late = new Promise<Answer<O>>((resolve) => {
    timer = $.clock.after(REQUEST_DEADLINE_MS, () => resolve({ ok: false, failure: 'timeout' }))
  })
  const sent = $.http
    .fetch(monitorUrl(op), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      socketPath,
    })
    .then(
      (res: { status: number; text: string }) => interpretReply(op, res.status, res.text),
      () => ({ ok: false, failure: 'unavailable' }) as Answer<O>,
    )
  try {
    return await Promise.race([sent, late])
  } finally {
    timer?.cancel()
  }
}

// Records what a request found: the legs it reported, or why it failed.
async function noteAnswer($: any, answer: Answer<Op>): Promise<void> {
  await update($, monitorState, () => (answer.ok ? 'ok' : answer.failure))
  if (!answer.ok) return
  const legs = answerLegs(answer.value)
  if (legs) await cacheLegs($, legs)
}

async function cacheLegs($: any, legs: Legs): Promise<void> {
  await update($, untrustedLeg, () => legs.untrusted)
  await update($, sensitiveLeg, () => legs.sensitive)
}

// Sessions this process registered, and the registrations in flight, so
// concurrent hooks send one register per session.
const registered = new Set<string>()
const registering = new Map<string, Promise<Answer<'register'>>>()

// Registers a session with the monitor. The first session of the process is
// the root of its lineage; any later one joins it. `fresh` is true only for a
// brand-new conversation (see isFreshSession), and only the root can be fresh:
// a session the monitor has never seen that is not fresh starts with its
// untrusted leg raised, because its history is not known to be clean.
function registerSession($: any, session: string, fresh: boolean): Promise<Answer<'register'>> {
  const pending = registering.get(session)
  if (pending) return pending
  const run = sendRegister($, session, fresh).finally(() => registering.delete(session))
  registering.set(session, run)
  return run
}

async function sendRegister($: any, session: string, fresh: boolean): Promise<Answer<'register'>> {
  let merged: Record<string, unknown> | null = null
  try {
    merged = await $.settings.read()
  } catch {
    // reportedPosture reports an unread posture as unsandboxed, so register is refused
  }
  if (!merged || typeof merged !== 'object') merged = null
  let root = await read($, rootSession)
  if (root === null) {
    root = session
    await update($, rootSession, (current: string | null) => current ?? session)
    root = (await read($, rootSession)) ?? session
  }
  const answer = await postMonitor($, 'register', {
    version: VERSION,
    host: HOST,
    session,
    root,
    fresh: fresh && root === session,
    posture: reportedPosture(merged),
  })
  await noteAnswer($, answer)
  if (answer.ok) registered.add(session)
  return answer
}

// One request about the current session. The session is registered first if
// this process has not registered it yet, and once more if the monitor no
// longer knows it (a new session id after /clear, or a monitor that lost it).
async function sessionRequest<O extends Exclude<Op, 'register' | 'health'>>(
  $: any,
  op: O,
  fields: Omit<Requests[O], 'version' | 'host' | 'session'>,
): Promise<Answer<O>> {
  const session = await $.session.id()
  if (typeof session !== 'string' || !TOKEN.test(session)) return { ok: false, failure: 'bad_request' }
  for (let attempt = 0; ; attempt++) {
    if (!registered.has(session)) {
      const reg = await registerSession($, session, false)
      if (!reg.ok) return reg
    }
    const answer = await postMonitor($, op, { version: VERSION, host: HOST, session, ...fields } as unknown as Requests[O])
    if (!answer.ok && answer.failure === 'unknown_session' && attempt === 0) {
      registered.delete(session)
      continue
    }
    await noteAnswer($, answer)
    return answer
  }
}

// Raises a leg for an event the shim detected itself, and records why. The
// first reason recorded for a leg wins.
async function observe($: any, source: Source, reason: string): Promise<Answer<'observe'>> {
  const answer = await sessionRequest($, 'observe', { source })
  if (answer.ok) await noteReason($, source === 'credential' ? 'sensitive' : 'untrusted', reason)
  return answer
}

async function noteReason($: any, leg: 'untrusted' | 'sensitive', reason: string): Promise<void> {
  if (leg === 'sensitive') await update($, sensitiveReason, (current: string | null) => current ?? reason)
  else await update($, untrustedReason, (current: string | null) => current ?? reason)
}

async function shownLegs($: any, legs: Legs): Promise<ShownLegs> {
  return {
    untrusted: legs.untrusted,
    sensitive: legs.sensitive,
    untrustedReason: legs.untrusted === 'none' ? null : await read($, untrustedReason),
    sensitiveReason: legs.sensitive === 'none' ? null : await read($, sensitiveReason),
  }
}

// What a step guarded by the monitor says when the monitor did not answer it.
function failureText(what: string, failure: Failure): string {
  return 'barmkin: ' + what + ' was denied because ' + describeFailure(failure) + '.'
}

// ---------------------------------------------------------------------------
// The egress gate.
// ---------------------------------------------------------------------------

// Marks leg B when a call names a secret-bearing path. Returns the failure if
// the monitor could not record it, so the caller denies the call.
async function noteSensitiveAccess($: any, call: EgressCall): Promise<Failure | null> {
  if (!touchesSecretPath(call, (await enforcedPolicy($)).secretPathPatterns)) return null
  const answer = await observe($, 'credential', 'a ' + call.tool + ' call named a credential path')
  return answer.ok ? null : answer.failure
}

// The egress gate for one call: notes any sensitive access in it, classifies
// it against the egress classes and asks the monitor for the verdict. A deny or
// warn is recorded for the status surface. Never answers allow, and any
// failure to reach the monitor denies.
async function egressGate($: any, call: EgressCall): Promise<EgressVerdict> {
  const unrecorded = await noteSensitiveAccess($, call)
  if (unrecorded) return { kind: 'deny', classIds: [], rule: 'untrusted', message: failureText('this call', unrecorded) }
  const classes = classifyEgress(call, (await enforcedPolicy($)).egressClasses)
  const answer = await sessionRequest($, 'decide', { classes: classes.map((c) => c.id as Class) })
  if (!answer.ok) return { kind: 'deny', classIds: classes.map((c) => c.id), rule: 'untrusted', message: failureText('this call', answer.failure) }
  const verdict = describeVerdict(answer.value, classes, await shownLegs($, answer.value.legs))
  if (verdict.kind !== 'pass') {
    await update($, lastEgress, () => ({
      tool: call.tool,
      classIds: verdict.classIds,
      decision: verdict.kind,
      rule: verdict.kind === 'deny' ? verdict.rule : answer.value.rule,
      at: Date.now(),
    }))
  }
  return verdict
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
async function decideSkillLoad($: any, name: string): Promise<string | null> {
  const answer = await sessionRequest($, 'decide', { classes: ['skill-load'] })
  if (!answer.ok) return failureText('loading this skill', answer.failure)
  if (answer.value.verdict === 'deny') {
    await update($, lastEgress, () => ({ tool: 'Skill', classIds: ['skill-load'], decision: 'deny' as const, rule: answer.value.rule, at: Date.now() }))
    const legs = await shownLegs($, answer.value.legs)
    const why = legs.untrustedReason ?? SOURCE_TEXT[legs.untrusted]
    return 'barmkin: loading a skill is blocked while this session is handling untrusted content (' + why + '). ' + STICKY_HINT
  }
  const raised = await observe($, 'skill', 'skill "' + name + '" was loaded')
  return raised.ok ? null : failureText('loading this skill', raised.failure)
}

// Raises the untrusted leg when a scrub stripped more than
// INVISIBLE_CHAR_TAINT_THRESHOLD characters. Returns the failure if the
// monitor could not record it.
async function taintForScrub($: any, hiddenCount: number, what: string): Promise<Failure | null> {
  if (hiddenCount <= INVISIBLE_CHAR_TAINT_THRESHOLD) return null
  const answer = await observe($, 'invisible', 'stripped ' + hiddenCount + ' invisible character(s) from ' + what)
  return answer.ok ? null : answer.failure
}

// ---------------------------------------------------------------------------
// The untrusted-content screen. The monitor scores and decides; the shim sends
// it the redacted windows and its local scores, and applies the decision.
// ---------------------------------------------------------------------------

type ScreenResult =
  | { decision: 'pass' | 'escalate' }
  | { decision: 'deny'; withholdReason: string }

// Screens one piece of untrusted content (a fetched page, an MCP result, a
// file read from outside cwd, an inbound peer message, a skill body). A deny
// withholds the content. A monitor that cannot screen it also withholds it:
// unscreened untrusted content never reaches Claude.
async function screenContent($: any, raw: string, source: Source, label: string, toolUseId: string | undefined): Promise<ScreenResult> {
  if (exceedsScreenedLimit(raw)) return { decision: 'deny', withholdReason: SCREENED_LIMIT_REASON }
  const scrubbed = scrubInvisible(raw).text
  const policy = await enforcedPolicy($)
  const scores: Scores = {
    injection: heuristicInjectionScore(scrubbed, policy.injectionPatterns),
    credentials: containsSecretInEitherView(raw, policy.redactionRules) ? 0.9 : 0,
    exfiltration: 0,
  }
  const input = classifierInput(raw, policy.redactionRules, redactionCounters)
  if (input === null) return { decision: 'deny', withholdReason: 'its redacted text could not be cut into screen windows' }
  if (input.length === 0) return { decision: 'pass' }
  const plan = planWindows(input)
  const windows = plan.windows.map((w) => input.slice(w.start, w.end))

  const answer = await sessionRequest($, 'screen', { source, windows, scores })
  if (!answer.ok) return { decision: 'deny', withholdReason: 'it could not be screened: ' + describeFailure(answer.failure) }
  const screened = answer.value

  // Text past the last window was never sent, so the screen could not vouch
  // for it: the content raises the untrusted leg whatever the windows scored.
  let decision = screened.decision
  if (plan.covered < input.length && decision === 'pass') {
    const raised = await observe($, source, label + ' ran past the screened windows')
    if (!raised.ok) return { decision: 'deny', withholdReason: 'it could not be screened: ' + describeFailure(raised.failure) }
    decision = 'escalate'
  }

  await update($, lastScreen, () => ({ toolUseId: toolUseId ?? '', label, decision, scores: screened.scores, gap: screened.gap, at: Date.now() }))
  if (decision !== 'pass') await noteReason($, 'untrusted', label + ' (' + describeScores(screened.scores) + ')')
  if (screened.legs.sensitive !== 'none') await noteReason($, 'sensitive', label + ' scored on the credential question')

  if (toolUseId) {
    try {
      $.ui.notice(toolUseId, 'barmkin: the monitor screened this ' + decision + ' (' + describeScores(screened.scores) + ')')
    } catch {
      // best-effort annotation only
    }
  }
  if (decision === 'deny') return { decision, withholdReason: 'the screen flagged it (' + describeScores(screened.scores) + ')' }
  return { decision }
}

function describeScores(scores: Scores): string {
  return 'injection ' + scores.injection.toFixed(2) + ', credentials ' + scores.credentials.toFixed(2) + ', exfiltration ' + scores.exfiltration.toFixed(2)
}

// What a withheld untrusted result tells Claude. A withhold for size alone is
// not a danger, so it points to paging; any other reason sends Claude back to
// the person.
function withheldMessage(what: string, reason: string): string {
  return 'barmkin: withheld ' + what + ' (' + reason + '). ' + (reason === SCREENED_LIMIT_REASON ? PAGING_ADVICE : 'Ask the user before retrying.')
}

// ---------------------------------------------------------------------------
// session.start: version and posture checks, register the session, commands.
// ---------------------------------------------------------------------------

// Whether the session is a brand-new conversation: nothing the model said or
// any tool returned is in it yet. A resumed or forked conversation carries
// its transcript, which may hold untrusted content, so it is not fresh. A
// failed read is not fresh either.
async function isFreshSession($: any): Promise<boolean> {
  try {
    const messages = await $.session.messages()
    return Array.isArray(messages) && messages.every((m: any) => m?.role === 'user' && !(m.toolResults?.length > 0))
  } catch {
    return false
  }
}

async function sessionStartHook($: any, e: any, next: any) {
  const statusLines: string[] = []

  try {
    const version = await $.session.version()
    const v = typeof version === 'string' ? version : version?.version
    if (typeof v === 'string' && !meetsMinimumVersion(v)) {
      statusLines.push('barmkin needs Claude Code >= ' + MIN_CLAUDE_CODE_VERSION + ' (running ' + v + '); some protections may not apply')
    }
  } catch {
    // $.session.version() unavailable on this build; nothing to warn about
  }

  let merged: Record<string, unknown> | null = null
  try {
    merged = await $.settings.read()
  } catch {
    // $.settings.read() unavailable or refused on this build; checkPosture reports it as unverified
  }
  if (typeof merged !== 'object') merged = null
  let policy: Record<string, unknown> | null = null
  try {
    policy = await $.settings.read({ source: 'policy' })
  } catch {
    // the policy source refused or unavailable; checkPosture reports seating as unverified
  }
  if (typeof policy !== 'object') policy = null
  const mcpAllowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
  for (const warning of checkPosture({ merged, policy }, PLUGIN_NAME, mcpAllowlist)) {
    statusLines.push('barmkin posture: ' + warning)
  }
  const rootPolicy = await currentPolicy($)
  if (rootPolicy.state === 'invalid') statusLines.push('barmkin policy: ' + describePolicy(rootPolicy))

  // Register now, so the first tool call does not wait for it. A failure is
  // reported here and retried by the first request that needs the session.
  try {
    const session = await $.session.id()
    if (typeof session === 'string' && TOKEN.test(session)) {
      const answer = await registerSession($, session, await isFreshSession($))
      if (!answer.ok) statusLines.push('barmkin: this session is not registered, so guarded tool calls are denied: ' + describeFailure(answer.failure))
      else await refreshStatus($)
    }
  } catch {
    statusLines.push('barmkin: this session could not be registered, so guarded tool calls are denied')
  }

  // $.ui.status holds one line per plugin and draws a newline as U+FFFD, so each warning is its own transcript row via $.ui.log.
  for (const line of statusLines) {
    try {
      $.ui.log(line)
    } catch {
      // no log surface on this build; the command below still registers
    }
  }

  try {
    await $.command.register({ name: 'barmkin-status', description: 'Show the barmkin taint legs, monitor and classifier state, and the last verdicts' })
  } catch {
    // a command name collided with another plugin; the shim still works
  }
  return next(e)
}

// Reads the session's legs and the classifier's state from the monitor.
async function refreshStatus($: any): Promise<Answer<'status'>> {
  const answer = await sessionRequest($, 'status', {})
  if (answer.ok) await update($, classifierState, () => answer.value.classifier)
  return answer
}

// ---------------------------------------------------------------------------
// session.append: pre-register each tool call before the managed gate asks.
//
// Claude Code 2.1.x runs the managed PreToolUse hook before any plugin hook,
// and a managed deny is final, so a plugin hook on the call itself would run
// too late. session.append sees each of the model's tool_use blocks, with the
// tool_use_id the gate will receive, before the call starts. A call that is
// not pre-registered is left for the gate to deny.
// ---------------------------------------------------------------------------

// toolUseIds lists the tool_use ids in a conversation row's blocks.
export function toolUseIds(content: readonly { type: string; [field: string]: unknown }[]): string[] {
  return content.filter((b) => b.type === 'tool_use').map((b) => (typeof b.id === 'string' ? b.id : ''))
}

async function preregisterHook($: any, e: any, next: any) {
  if (e.message?.type !== 'assistant' || !Array.isArray(e.message.content)) return next(e)
  const calls = toolUseIds(e.message.content)
  if (calls.length === 0) return next(e)
  const results = await Promise.all(calls.map((call) => preregisterCall($, call)))
  results.forEach((failure, i) => {
    if (failure) $.ui.log('barmkin: tool call ' + (calls[i] || '(no id)') + ' was not pre-registered (' + describeFailure(failure) + '); the barmkin gate will deny it')
  })
  return next(e)
}

async function preregisterCall($: any, call: string): Promise<Failure | null> {
  if (!TOKEN.test(call)) return 'bad_request'
  const answer = await sessionRequest($, 'preregister', { call })
  return answer.ok ? null : answer.failure
}

// The shim never holds up the conversation: a row it could not pre-register
// still lands, and the gate denies its calls.
async function preregisterCatch($: any, e: any, next: any) {
  return next(e)
}

// ---------------------------------------------------------------------------
// prompt.submit: redact secrets the user pasted. No prompt clears the taint.
// ---------------------------------------------------------------------------

async function promptSubmitHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string') return next(e)
  if (exceedsScreenedLimit(e.text)) {
    return { drop: 'barmkin: your message is longer than the 16 KiB scan limit, so it was withheld' }
  }
  // Detection runs on the scrubbed view; the original text is forwarded unless a secret is redacted.
  const { text, redactedCount } = redactInEitherView(e.text, await enforcedPolicy($))
  if (redactedCount === 0) return next(e)
  if (text === WITHHELD_TEXT) {
    return { drop: 'barmkin: your message could not be fully scanned after redaction, so it was withheld' }
  }
  $.ui.log('barmkin: redacted ' + redactedCount + ' likely secret(s) from your message before sending it')
  return next({ ...e, text })
}

// ---------------------------------------------------------------------------
// MCP tool-poisoning guard: harden descriptions, per-server allowlist.
// ---------------------------------------------------------------------------

async function toolDescribeHook($: any, e: any, next: any) {
  const current = await next(e)
  const description = typeof current?.description === 'string' ? current.description : e.description
  if (typeof description !== 'string') return current

  const scrubbed = scrubInvisible(description)
  const unrecorded = await taintForScrub($, scrubbed.hiddenCount, 'an MCP tool description')
  if (unrecorded) {
    $.ui.log('barmkin: withheld an MCP tool description (' + describeFailure(unrecorded) + ')')
    return { ...current, description: failureText('this tool description', unrecorded) + ' It hid invisible characters.' }
  }

  const { description: cleaned, flagged } = neutralizeDescription(scrubbed.text)
  if (!flagged) {
    return scrubbed.text === description ? current : { ...current, description: scrubbed.text }
  }
  $.ui.log('barmkin: flagged instruction-like text in a tool description (' + e.tool + ')', { to: 'debug' })
  if (cleaned === description) return current
  return { ...current, description: cleaned }
}

async function mcpGuardHook($: any, e: any, next: any) {
  const serverName = parseMcpServerName(e.tool)
  if (serverName) {
    const allowlist = parseAllowlist(pluginOptions.mcp_server_allowlist)
    if (!isAllowedServer(serverName, allowlist)) {
      return { deny: 'barmkin: MCP server "' + serverName + '" is not on the allowlist' }
    }
  }

  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }

  const result = await next(e)
  if (!result || result.deny || result.isError) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'mcp', 'mcp:' + (serverName ?? e.tool), e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage('this MCP result', verdict.withholdReason))
  }
  if (verdict.decision === 'escalate') return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function mcpGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin: the MCP guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Egress and untrusted content.
// ---------------------------------------------------------------------------

// One gate for every egress class that is not an MCP call or a skill load:
// shell commands (Bash/PowerShell and Monitor's `command`), web fetches and
// searches, Monitor WebSockets, and persistence-surface writes. A deny answers
// before the tool runs; a warn lets it run and tells Claude.
async function egressGuardHook($: any, e: any, next: any) {
  const egress = await egressGate($, { tool: e.tool, input: e })
  if (egress.kind === 'deny') return { deny: egress.message }
  const result = await next(e)
  if (egress.kind === 'warn' && result && !result.deny && !result.isError) return appendContext(result, egress.message)
  return result
}

async function egressGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin: the egress guard failed (' + next.error.kind + '), so this call was not run' }
}

// ---------------------------------------------------------------------------
// Mediation guard. A skill's inline shell (`!`command``) runs the command
// through the permission check but never through the mods' tool.call chain, so
// none of the tool.call guards above see it; tool.check is the one event it
// does fire, with an empty tool_use_id. This hook only ever answers deny or
// returns what the permission layer decided, never allow or ask.
// ---------------------------------------------------------------------------

async function toolCheckGuardHook($: any, e: any, next: any) {
  const decided = await next(e)
  if (decided && decided.decision === 'deny') return decided
  const input = e.input && typeof e.input === 'object' ? (e.input as Record<string, unknown>) : null
  if (!input || typeof input.command !== 'string') return decided

  const call: EgressCall = { tool: e.tool, input }
  if (isInlineSkillShell(e.tool_use_id)) {
    const policy = await enforcedPolicy($)
    const reason = inlineShellDenyReason(call, policy.egressClasses, policy.secretPathPatterns)
    if (reason) return { decision: 'deny', reason }
  }
  // Second line for an ordinary call: the same egress verdict the tool.call
  // guard reached, in case the command was rewritten after it.
  const egress = await egressGate($, call)
  if (egress.kind === 'deny') return { decision: 'deny', reason: egress.message }
  return decided
}

async function toolCheckGuardCatch($: any, e: any, next: any) {
  return { decision: 'deny', reason: 'barmkin: the shell mediation guard failed (' + next.error.kind + '), so this command was not run' }
}

async function webFetchTaintHook($: any, e: any, next: any) {
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'fetch', 'fetch:' + e.tool, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage('this result', verdict.withholdReason))
  }
  if (verdict.decision === 'escalate') return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function readTaintHook($: any, e: any, next: any) {
  const unrecorded = await noteSensitiveAccess($, { tool: e.tool, input: e })
  if (unrecorded) return { deny: failureText('this Read', unrecorded) }
  const result = await next(e)
  if (!result || result.deny || result.isError) return result
  if (typeof e.file_path !== 'string') return result

  if (!(await screenedSurface($, e))) return result

  const text = extractResultText(result)
  if (!text) return result
  const verdict = await screenContent($, text, 'read', 'read:' + e.file_path, e.tool_use_id)
  if (verdict.decision === 'deny') {
    return withholdResult(result, withheldMessage("this file's content", verdict.withholdReason))
  }
  // appendContext only adds a sibling `context` array alongside whatever
  // `result` already is -- it never touches `result`'s own shape -- so this
  // stays schema-valid for Read's `{ file: { content, ... } }` record the
  // same way it already is for every other tool here.
  if (verdict.decision === 'escalate') return appendContext(result, UNTRUSTED_CONTENT_WARNING)
  return result
}

async function taintScreenCatch($: any, e: any, next: any) {
  return { deny: 'barmkin: the content screen failed (' + next.error.kind + '), so this result was withheld' }
}

// ---------------------------------------------------------------------------
// Secret redaction. Outermost tool.call hook (registered first, so it wraps
// every other hook above and redacts the final composed result -- including
// any context a later hook in this file added -- before Claude reads it).
// ---------------------------------------------------------------------------

// Read's image variant carries its payload as base64 at result.result.base64
// (flat) or result.result.file.base64 (file record). Gated on the Read tool so
// an MCP result cannot hide plaintext there.
function readImageBase64(e: any, result: any): string | undefined {
  const payload = result.result
  if (e.tool !== 'Read' || !payload || typeof payload !== 'object' || payload.type !== 'image') return undefined
  const base64 = typeof payload.base64 === 'string' ? payload.base64 : payload.file?.base64
  return typeof base64 === 'string' ? base64 : undefined
}

// Decodes an image payload that already passed the per-string cap and runs the
// rules over its bytes, so a secret in a plaintext file with an image extension
// is caught. The base64 text itself also goes through the normal redaction pass.
function imagePayloadWithholdReason(base64: string, policy: ActivePolicy): string | null {
  let bytes: string
  try {
    bytes = atob(base64)
  } catch {
    return 'this Read image payload is not valid base64'
  }
  return containsAnySecret(bytes, policy.redactionRules) ? 'this Read image payload contains a secret-shaped value' : null
}

// A result shows a scanned prefix only when its payload is text: cutting a
// base64 image or PDF leaves something that is not one. A result with no
// `result` has nothing to cut.
function prefixable(result: any): boolean {
  if (!('result' in result)) return false
  const payload = result.result
  if (!payload || typeof payload !== 'object') return true
  const binary = payload.type === 'image' || payload.type === 'pdf' || 'base64' in payload || (!!payload.file && typeof payload.file === 'object' && 'base64' in payload.file)
  return !binary
}

// Whether an injection screen covers this tool's result: an MCP tool, WebFetch,
// WebSearch, and a Read outside cwd. Each withholds at the 16 KiB screened limit
// inside `next(e)`, so a result that reaches the redaction hook over that limit
// came from a tool with no screen, or from a Read whose screen could not run
// (the cwd lookup failed, which is treated as outside). This hook keeps those
// at the screened limit too, so raising the redaction cap never lets unscreened
// untrusted text in.
async function screenedSurface($: any, e: any): Promise<boolean> {
  if (typeof e.tool !== 'string') return true
  if (parseMcpServerName(e.tool) || e.tool === 'WebFetch' || e.tool === 'WebSearch') return true
  if (e.tool !== 'Read' || typeof e.file_path !== 'string') return false
  try {
    return isOutsideCwd(e.file_path, await $.session.cwd())
  } catch {
    return true
  }
}

async function redactionHook($: any, e: any, next: any) {
  const result = await next(e)
  if (!result || result.deny) return result
  // Within the screened limits nothing depends on which tool this is. Over them,
  // only a tool that no screen covers gets the larger redaction limits.
  let size = measureResult(result, true)
  if (size !== 'within' && !(await screenedSurface($, e))) size = measureResult(result)
  const showPrefix = size === 'long-string' && prefixable(result)
  if (size === 'over-total' || (size === 'long-string' && !showPrefix)) {
    return { deny: 'barmkin: this tool result is larger than the redaction scan budget, so it was withheld. ' + PAGING_ADVICE }
  }

  const policy = await enforcedPolicy($)
  const imageBase64 = readImageBase64(e, result)
  const imageReason = imageBase64 === undefined ? null : imagePayloadWithholdReason(imageBase64, policy)
  if (imageReason) return { deny: 'barmkin: ' + imageReason + ', so it was withheld' }

  let changed = false
  let hiddenCount = 0
  let redactionHits = 0
  let noSafeCut = false
  const cuts = new Map<string, string>()
  const next_: any = { ...result }

  // Every string inside the result is rewritten in place, whatever its
  // shape: a plain string, an MCP content-block array, or a built-in tool's
  // typed record (Bash `{stdout, stderr, ...}`, Read `{file: {content}}`).
  // The record keeps its shape so core's output-schema validation passes.
  // Core's model-visible rendering in `text` is redacted the same way.
  // Scrubbed before redaction: a zero-width character spliced into a
  // token shouldn't be able to help it dodge a secret pattern either.
  // A string over the per-string cap, in a result that may show one, is
  // replaced by its scanned prefix, and its invisible-text count covers the
  // whole string.
  const redactValue = (value: unknown): unknown => {
    if (typeof value === 'string') {
      if (showPrefix && exceedsScanLimit(value)) {
        const prefix = scannedPrefix(value, policy.redactionRules, redactionCounters)
        if (prefix === null) {
          noSafeCut = true
          return value
        }
        hiddenCount += prefix.hiddenCount
        redactionHits += prefix.redactedCount
        cuts.set(prefix.cut + '/' + prefix.total, prefixNotice(prefix.cut, prefix.total))
        changed = true
        return prefix.shown
      }
      const scrubbed = scrubInvisible(value)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(value, policy)
      redactionHits += redactedCount
      if (redactedCount === 0 && scrubbed.strippedCount === 0) return value
      changed = true
      return redacted
    }
    if (Array.isArray(value)) return value.map(redactValue)
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactValue(v)]))
    }
    return value
  }
  if ('result' in result) next_.result = redactValue(result.result)
  const hiddenInResult = hiddenCount
  hiddenCount = 0
  if (typeof result.text === 'string') next_.text = redactValue(result.text)
  hiddenCount = Math.max(hiddenInResult, hiddenCount)

  if (Array.isArray(result.context)) {
    const redactedContext = result.context.map((c: unknown) => {
      if (typeof c !== 'string') return c
      const scrubbed = scrubInvisible(c)
      hiddenCount += scrubbed.hiddenCount
      const { text: redacted, redactedCount } = redactInEitherView(c, policy)
      redactionHits += redactedCount
      if (redactedCount > 0 || scrubbed.strippedCount > 0) changed = true
      return redacted
    })
    next_.context = redactedContext
  }

  if (noSafeCut) {
    return { deny: 'barmkin: this tool result is larger than the redaction scan budget and has no safe place to cut it, so it was withheld. ' + PAGING_ADVICE }
  }

  // A redaction hit means a credential-shaped value just passed through this
  // session: leg B of the trifecta. Raised before returning, so the very next
  // egress call sees it. A leg the monitor could not record withholds the
  // result, as does an invisible-text payload it could not record.
  if (redactionHits > 0) {
    const raised = await observe($, 'credential', 'a ' + (parseMcpServerName(e.tool) ? 'tool' : e.tool) + ' result held a credential-shaped value')
    if (!raised.ok) return { deny: failureText('this result', raised.failure) + ' It held a credential-shaped value.' }
  }
  const unrecorded = await taintForScrub($, hiddenCount, 'tool:' + (typeof e.tool === 'string' && parseMcpServerName(e.tool) ? 'mcp' : e.tool))
  if (unrecorded) return { deny: failureText('this result', unrecorded) + ' It hid invisible characters.' }

  if (!showPrefix) return changed ? next_ : result

  // A fresh answer, without core's `ref` and `text`: core then validates the
  // record against the tool's output schema and maps it for the model itself,
  // rather than reusing its own rendering of the full output. An errored
  // result has no output schema, so it keeps its error text.
  const fresh: any = { result: next_.result, context: [...(next_.context ?? []), ...cuts.values()] }
  if (result.isError) {
    fresh.isError = true
    if ('text' in next_) fresh.text = next_.text
  }
  // Read's line count describes the content it now carries.
  const file = fresh.result?.file
  if (cuts.size > 0 && file && typeof file.content === 'string' && typeof file.numLines === 'number') {
    fresh.result = { ...fresh.result, file: { ...file, numLines: file.content.split('\n').length } }
  }
  return fresh
}

async function redactionCatch($: any, e: any, next: any) {
  // Fail closed regardless of whether the tool already ran (next.called):
  // we can't un-run a command, but we can stop an unredacted result from
  // reaching the model or the transcript.
  return { deny: 'barmkin: secret redaction failed (' + next.error.kind + '); the result was withheld to avoid leaking an unredacted secret' }
}

// ---------------------------------------------------------------------------
// Agent-to-agent firewall.
// ---------------------------------------------------------------------------

async function sessionReceiveHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string' || e.text.length === 0) return next(e)

  const scrubbed = scrubInvisible(e.text)
  const unrecorded = await taintForScrub($, scrubbed.hiddenCount, 'an inbound peer message')
  if (unrecorded) return { consumed: 'barmkin: withheld an inbound message (' + describeFailure(unrecorded) + ')' }
  if (exceedsScreenedLimit(e.text)) {
    return { consumed: 'barmkin: withheld an inbound message (it is longer than the 16 KiB scan limit)' }
  }

  const verdict = await screenContent($, e.text, 'peer', 'peer:' + (e.origin?.kind ?? 'unknown'), undefined)
  if (verdict.decision === 'deny') {
    return { consumed: 'barmkin: withheld an inbound message (' + verdict.withholdReason + ')' }
  }
  return next(scrubbed.text === e.text ? e : { ...e, text: scrubbed.text })
}

async function sessionReceiveCatch($: any, e: any, next: any) {
  return { consumed: 'barmkin: the a2a screen failed (' + next.error.kind + '); message withheld' }
}

async function sessionSendHook($: any, e: any, next: any) {
  if (typeof e.text !== 'string') return next(e)
  if (exceedsScreenedLimit(e.text)) {
    return { isDelivered: false, reason: 'barmkin: message withheld, it is longer than the 16 KiB scan limit' }
  }
  // Detection runs on the scrubbed view; the original text is delivered when no secret is found.
  if (containsSecretInEitherView(e.text, (await enforcedPolicy($)).redactionRules)) {
    return { isDelivered: false, reason: 'barmkin: message withheld, it appears to contain a secret' }
  }
  return next(e)
}

async function sessionSendCatch($: any, e: any, next: any) {
  return { isDelivered: false, reason: 'barmkin: the DLP screen failed (' + next.error.kind + '); message not sent' }
}

async function agentSpawnHook($: any, e: any, next: any) {
  const answer = await refreshStatus($)
  if (!answer.ok) return { deny: failureText('this subagent spawn', answer.failure) }
  if (answer.value.legs.untrusted !== 'none') {
    const legs = await shownLegs($, answer.value.legs)
    return {
      deny:
        'barmkin: subagent spawn blocked while this session is tainted (' +
        (legs.untrustedReason ?? SOURCE_TEXT[legs.untrusted]) +
        '). ' +
        STICKY_HINT,
    }
  }
  return next(e)
}

async function agentSpawnCatch($: any, e: any, next: any) {
  return { deny: 'barmkin: the a2a spawn guard failed (' + next.error.kind + '); subagent spawn blocked' }
}

// ---------------------------------------------------------------------------
// Skill content. skill.prompt fires with each skill body, after inline-shell
// output is substituted, for inline, context: fork and agent-preloaded skills.
// Its payload is { skill: <name string>, text }; the dispatcher rejects a
// changed `skill`, so only `text` is ever rewritten. Org seat only: sec-default
// forwards skill.prompt past the user tier, so this fires only when the shim is
// seated in managed prependPlugins ahead of sec-default. Like toolDescribeHook,
// it calls next first and screens and redacts the text that came out, so
// redaction sees the final body last.
// ---------------------------------------------------------------------------

async function skillPromptHook($: any, e: any, next: any) {
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  const unrecorded = await taintForScrub($, scrubInvisible(text).hiddenCount, 'a skill body')
  if (unrecorded) return { ...(current ?? e), text: skillBodyWithheldText(describeFailure(unrecorded)) }
  const verdict = await screenContent($, text, 'skill', 'skill:' + e.skill, undefined)
  if (verdict.decision === 'deny') {
    return { ...(current ?? e), text: skillBodyWithheldText(verdict.withholdReason) }
  }

  const { text: redacted, redactedCount } = redactInEitherView(text, await enforcedPolicy($))
  if (redacted === WITHHELD_TEXT) {
    return { ...(current ?? e), text: skillBodyWithheldText('the redacted body exceeds the 256 KiB scan limit') }
  }
  if (redactedCount > 0) {
    $.ui.log('barmkin: redacted ' + redactedCount + ' likely secret(s) from skill ' + e.skill)
  }
  const body = verdict.decision === 'escalate' ? redacted + '\n\n' + UNTRUSTED_CONTENT_WARNING : redacted
  return { ...(current ?? e), text: body }
}

async function skillPromptCatch($: any, e: any, next: any) {
  return { skill: e.skill, text: skillBodyWithheldText('the skill screen failed (' + next.error.kind + ')') }
}

// A skill listing is `prompt.attachment{type:'skill_listing', text}`, one per
// session and one per spawned subagent. The hook is registered for that type
// only, so other attachments never reach it or its catch. The dispatcher honours
// a rewritten `text` and rejects a change to `type`, `origin`, `agentId` or `detail`.
async function skillListingHook($: any, e: any, next: any) {
  const current = await next(e)
  const text = typeof current?.text === 'string' ? current.text : e.text
  if (typeof text !== 'string') return current ?? e

  const { text: neutralized, withheld } = neutralizeSkillListing(scrubInvisible(text).text)
  if (withheld > 0) $.ui.log('barmkin: withheld ' + withheld + ' skill listing entr' + (withheld === 1 ? 'y' : 'ies') + ' with instruction-like text', { to: 'debug' })
  if (neutralized === text) return current ?? e
  return { ...(current ?? e), text: neutralized }
}

async function skillListingCatch($: any, e: any, next: any) {
  return { ...e, text: skillListingWithheldText('the listing screen failed (' + next.error.kind + ')') }
}

// Gates the Skill tool itself. A loaded skill is untrusted content in its own
// right: its body is screened by skillPromptHook, and the load raises the
// untrusted leg so later outward-effect calls and further skill loads are held
// for the rest of the session. The leg is raised before the load runs, and
// loads are decided one at a time, so concurrent loads cannot both pass, and a
// failed or denied load still leaves the session tainted.
async function skillToolGuardHook($: any, e: any, next: any) {
  const name = typeof e.skill === 'string' ? e.skill : 'unnamed'
  const denied = await serializeSkillLoad(() => decideSkillLoad($, name))
  if (denied) return { deny: denied }
  return next(e)
}

async function skillToolGuardCatch($: any, e: any, next: any) {
  return { deny: 'barmkin: the skill guard failed (' + next.error.kind + '), so this skill was not loaded' }
}

// ---------------------------------------------------------------------------
// Explanation surface: HUD band, prompt hint and the status command. The HUD
// and the hint read the cached state only and never wait on the monitor.
// ---------------------------------------------------------------------------

// The tainted-session panel's color: the theme's error key, red in every
// theme, so the panel matches how the session draws its own errors.
const TAINT_COLOR = 'error'

// The clear-session labels: the theme's success key (green) and warning key
// (amber); both labels lead with a castle emoji. Green means the monitor
// answered the last request and its classifier is up; it does not claim any
// screen succeeded. Amber means the monitor's classifier is degraded, or the
// last request to the monitor failed.
const CLEAR_ACTIVE = { color: 'success', label: '🏰 Barmkin session guard active' }
const CLEAR_DEGRADED = { color: 'warning', label: '🏰 Barmkin session guard degraded' }

// The HUD's tainted-session line: untrusted content is active, what that
// restricts, and that it holds for the rest of the session.
export function describeTaintBanner(sensitive: boolean): string {
  const restriction = sensitive ? '\u{1F6AB} all outbound actions blocked' : '\u{1F6AB} outbound actions may be restricted'
  return '\u{1F6A8} TAINTED: untrusted content active · ' + restriction + ' · sticky: start a new session to work without it'
}

async function readShown($: any): Promise<ShownLegs> {
  return shownLegs($, { untrusted: await read($, untrustedLeg), sensitive: await read($, sensitiveLeg) })
}

async function hudHook($: any, e: any, next: any) {
  const legs = await readShown($)
  const isTainted = legs.untrusted !== 'none'
  const isSensitive = legs.sensitive !== 'none'
  const screen = await read($, lastScreen)
  const monitor = await read($, monitorState)
  const classifier = await read($, classifierState)

  const { Box, Text } = $.ui.resolve(e)
  const parts = ['barmkin', 'taint:' + (isTainted ? 'ON' : 'off'), monitor === 'ok' ? 'monitor:ok' : 'monitor:' + monitor, 'classifier:' + classifier]
  if (isSensitive) parts.splice(2, 0, isTainted ? 'sensitive:ON (egress locked)' : 'sensitive:ON')
  if (screen) parts.push('last screen: ' + screen.decision)

  let banner = null
  if (isTainted) {
    banner = Box({
      key: 'barmkin-taint',
      children: [Text({ color: TAINT_COLOR, bold: true, children: [describeTaintBanner(isSensitive)] })],
    })
  }

  // next(e) may resolve to nothing if no other mod draws in the band, so
  // filter out a falsy child rather than assume an engine placeholder.
  // The state line below appears only when there is state to report.
  const stateLine = isTainted || isSensitive || screen || monitor !== 'ok' ? Text({ children: [parts.join(' · ')] }) : null
  const theirs = await next(e)
  return Box({ flexDirection: 'column', children: [theirs, banner, stateLine].filter(Boolean) })
}

// The clear-session label draws as a second child of the PromptHint footer,
// directly beneath the engine's own line (mode switcher included). While
// tainted the red banner in AbovePrompt speaks instead, so the engine's
// drawing is returned unchanged.
async function hintHook($: any, e: any, next: any) {
  const theirs = await next(e)
  if ((await read($, untrustedLeg)) !== 'none') return theirs
  const { Box, Text } = $.ui.resolve(e)
  const healthy = (await read($, monitorState)) === 'ok' && (await read($, classifierState)) === 'ok'
  const clear = healthy ? CLEAR_ACTIVE : CLEAR_DEGRADED
  const label = Text({ key: 'barmkin-active', color: clear.color, children: [clear.label] })
  return Box({ flexDirection: 'column', children: [theirs, label].filter(Boolean) })
}

async function statusCommandHook($: any) {
  const answer = await refreshStatus($)
  const legs = await readShown($)
  const egress = await read($, lastEgress)
  const screen = await read($, lastScreen)
  const leg = (source: Source, reason: string | null) => (source === 'none' ? 'off' : 'ON (' + (reason ?? SOURCE_TEXT[source]) + ')')
  const lines = [
    'barmkin status',
    'monitor: ' + (answer.ok ? 'ok' : describeFailure(answer.failure) + '; guarded tool calls are denied until it answers'),
    'taint: ' + leg(legs.untrusted, legs.untrustedReason),
    'sensitive access: ' + leg(legs.sensitive, legs.sensitiveReason),
    'the taint is sticky: nothing clears it in this session; a new session starts clean',
    'egress: ' +
      (legs.untrusted !== 'none' && legs.sensitive !== 'none'
        ? 'all classes denied (Rule of Two)'
        : legs.untrusted !== 'none'
          ? 'gated per class (taint)'
          : 'open') +
      (egress ? '; last ' + egress.decision + ': ' + egress.classIds.join(', ') + ' via ' + egress.tool + ' (' + egress.rule + ')' : ''),
    'classifier: ' + (answer.ok ? answer.value.classifier : await read($, classifierState)) + ' (screened by the monitor)',
    screen ? 'last screen: ' + screen.decision + ' for ' + screen.label + ' (' + describeScores(screen.scores) + (screen.gap !== 'none' ? '; gap ' + screen.gap : '') + ')' : 'last screen: none yet',
    'policy: ' + describePolicy(await currentPolicy($)),
  ]
  return { text: lines.join('\n') }
}

// ---------------------------------------------------------------------------
// Registration. Order matters for tool.call: the first hook registered is
// outermost (sees the result last), so redaction is registered first to
// redact whatever every other hook below it produced.
// ---------------------------------------------------------------------------

export function register(on: any, options: Record<string, unknown>) {
  pluginOptions = options ?? {}

  on('session.start', sessionStartHook)
  on('session.append', preregisterHook).catch(preregisterCatch)
  on('prompt.submit', promptSubmitHook)
  on('tool.describe', { tool: /^mcp__/ }, toolDescribeHook)

  on('tool.call', redactionHook).catch(redactionCatch)
  on('tool.call', { tool: /^mcp__/ }, mcpGuardHook).catch(mcpGuardCatch)
  on('tool.call', { tool: ['Bash', 'PowerShell', 'WebFetch', 'WebSearch', 'Monitor', 'Edit', 'Write', 'MultiEdit', 'NotebookEdit'] }, egressGuardHook).catch(egressGuardCatch)
  on('tool.call', { tool: ['WebFetch', 'WebSearch'] }, webFetchTaintHook).catch(taintScreenCatch)
  on('tool.call', { tool: 'Read' }, readTaintHook).catch(taintScreenCatch)

  on('tool.call', { tool: 'Skill' }, skillToolGuardHook).catch(skillToolGuardCatch)
  on('tool.check', { tool: ['Bash', 'PowerShell', 'Monitor'] }, toolCheckGuardHook).catch(toolCheckGuardCatch)

  on('skill.prompt', skillPromptHook).catch(skillPromptCatch)
  on('prompt.attachment', { type: 'skill_listing' }, skillListingHook).catch(skillListingCatch)

  on('session.receive', sessionReceiveHook).catch(sessionReceiveCatch)
  on('session.send', sessionSendHook).catch(sessionSendCatch)
  on('agent.spawn', agentSpawnHook).catch(agentSpawnCatch)
  on('ui.render', { component: 'AbovePrompt' }, hudHook)
  on('ui.render', { component: 'PromptHint' }, hintHook)
  on('command.run', { command: 'barmkin-status' }, statusCommandHook)
}
