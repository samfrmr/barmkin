// An in-memory barmkin monitor for the shim's tests: the contract in
// hooks/lib/proto.ts with the monitor's behaviour (internal/monitor), and a
// stand-in screen. Every request is decoded strictly, so a request the shim
// encodes wrongly fails here as it would against the real monitor.
//
// It imports no test kit, so the contract test (monitor-contract.test.ts,
// run under node against a real `barmkin monitor`) can check decideLike
// against the real decide.

import {
  CLASSES,
  HTTP_STATUS,
  ProtoError,
  VERSION,
  decodeRequest,
  encodeError,
  encodeResponse,
  parsePath,
  type Class,
  type Code,
  type Legs,
  type Op,
  type Requests,
  type Responses,
  type Rule,
  type ScreenDecision,
  type Scores,
  type Source,
  type Verdict,
} from '../../hooks/lib/proto.ts'

// The class postures table, as internal/monitor/decide.go holds it.
export const POSTURES: Readonly<Record<Class, { denyOnUntrusted: boolean; warnWhenClean: boolean }>> = Object.fromEntries(
  CLASSES.map((c) => [c, { denyOnUntrusted: false, warnWhenClean: false }]),
) as Record<Class, { denyOnUntrusted: boolean; warnWhenClean: boolean }>
for (const c of ['shell-outward', 'net-client', 'interpreter-net', 'web-fetch', 'monitor-ws', 'mcp-write', 'skill-load'] as const) {
  POSTURES[c].denyOnUntrusted = true
}
for (const c of ['destructive', 'history-rewrite'] as const) {
  POSTURES[c].denyOnUntrusted = true
  POSTURES[c].warnWhenClean = true
}

// decideLike is the monitor's decide: pass a clean session except for the
// destructive classes, which warn; deny every class with both legs up; with
// the untrusted leg up, deny the classes that deny on it, else warn on all.
export function decideLike(classes: readonly Class[], legs: Legs): { verdict: Verdict; rule: Rule; classes: Class[] } {
  const pass = { verdict: 'pass' as Verdict, rule: 'none' as Rule, classes: [] as Class[] }
  if (classes.length === 0) return pass
  const pick = (keep: (p: { denyOnUntrusted: boolean; warnWhenClean: boolean }) => boolean) => classes.filter((c) => keep(POSTURES[c]))
  if (legs.untrusted === 'none') {
    const advisory = pick((p) => p.warnWhenClean)
    return advisory.length > 0 ? { verdict: 'warn', rule: 'none', classes: advisory } : pass
  }
  if (legs.sensitive !== 'none') return { verdict: 'deny', rule: 'rule_of_two', classes: [...classes] }
  const denied = pick((p) => p.denyOnUntrusted)
  if (denied.length > 0) return { verdict: 'deny', rule: 'untrusted', classes: denied }
  return { verdict: 'warn', rule: 'none', classes: [...classes] }
}

// The screen's thresholds (internal/screen/compose.go).
export const TAINT_AT = 0.5
export const DENY_AT = 0.85

// What the stand-in screen answers. 'local' decides on the shim's local
// scores as the monitor's screen does with no classifier; 'unavailable' is
// the monitor core without a screen service: it raises the untrusted leg and
// fails. A function answers per request.
export type ScreenMode = 'local' | 'unavailable' | ((req: Requests['screen']) => { decision: ScreenDecision; scores: Scores })

export interface FakeMonitorOptions {
  screen?: ScreenMode
}

export interface Reply {
  status: number
  text: string
}

export class FakeMonitor {
  // Every request received, decoded, in order.
  readonly requests: { op: Op; body: Requests[Op] }[] = []
  // Raw request bodies, to check that nothing but the screen windows carries content.
  readonly bodies: string[] = []
  screen: ScreenMode
  // down: requests fail as an unreachable socket does. hang: they never answer.
  down = false
  hang = false
  // Answers every request with this error code instead.
  failWith: Code | null = null
  // Answers every request with this raw body and status.
  rawReply: Reply | null = null
  // What status reports for the classifier. The monitor core has none yet.
  classifier: 'ok' | 'degraded' = 'degraded'
  sessions = new Map<string, string>()
  lineages = new Map<string, Legs>()
  preregistered = new Map<string, number>()

  constructor(opts: FakeMonitorOptions = {}) {
    this.screen = opts.screen ?? 'local'
  }

  // restart loses every session, as a monitor whose journal was lost does.
  forgetSessions(): void {
    this.sessions.clear()
    this.lineages.clear()
    this.preregistered.clear()
  }

  legsOf(session: string): Legs | undefined {
    const root = this.sessions.get(session)
    return root === undefined ? undefined : this.lineages.get(root)
  }

  count(op: Op): number {
    return this.requests.filter((r) => r.op === op).length
  }

  // handle answers one request as the monitor would: path, then body.
  handle(url: string, body: string): Reply {
    if (this.rawReply) return this.rawReply
    const path = url.replace(/^http:\/\/[^/]+/, '')
    const op = parsePath(path)
    if (!op) return this.error('bad_request')
    this.bodies.push(body)
    let req: Requests[Op]
    try {
      req = decodeRequest(op, body)
    } catch (err) {
      return this.error(err instanceof ProtoError ? err.code : 'bad_request')
    }
    this.requests.push({ op, body: req })
    if (this.failWith) return this.error(this.failWith)
    const answer = this.answer(op, req)
    if ('error' in answer) return this.error(answer.error)
    return { status: 200, text: encodeResponse(op, answer as Responses[typeof op]) }
  }

  private error(code: Code): Reply {
    return { status: HTTP_STATUS[code], text: encodeError({ version: VERSION, error: code }) }
  }

  private raise(session: string, source: Source): Legs {
    const root = this.sessions.get(session)!
    const legs = this.lineages.get(root)!
    if (source === 'credential') {
      if (legs.sensitive === 'none') legs.sensitive = source
    } else if (legs.untrusted === 'none') {
      legs.untrusted = source
    }
    return { ...legs }
  }

  private answer(op: Op, req: any): Responses[Op] | { error: Code } {
    if (op === 'health') return { version: VERSION, state: 'ok' }
    if (op === 'register') return this.register(req)
    const legs = this.legsOf(req.session)
    if (!legs) return { error: 'unknown_session' }
    switch (op) {
      case 'preregister':
        this.preregistered.set(req.session + '/' + req.call, Date.now())
        return { version: VERSION, ttl_ms: 10000 }
      case 'gate': {
        const key = req.session + '/' + req.call
        const live = this.preregistered.delete(key)
        return { version: VERSION, preregistered: live }
      }
      case 'decide':
        return { version: VERSION, ...decideLike(req.classes, legs), legs: { ...legs } }
      case 'observe':
        return { version: VERSION, legs: this.raise(req.session, req.source) }
      case 'status':
        return { version: VERSION, legs: { ...legs }, classifier: this.classifier }
      case 'screen':
        return this.screenAnswer(req)
    }
    return { error: 'bad_request' }
  }

  private register(req: Requests['register']): Responses['register'] | { error: Code } {
    if (!req.posture.sandbox_enabled || req.posture.allow_all_unix_sockets) return { error: 'posture_refused' }
    const have = this.sessions.get(req.session)
    const root = this.sessions.get(req.root) ?? req.root
    if (have !== undefined) {
      if (root !== have && req.root !== have) return { error: 'bad_request' }
      return { version: VERSION, legs: { ...this.lineages.get(have)! } }
    }
    const seen = this.lineages.has(root)
    this.sessions.set(req.session, root)
    if (!seen) this.lineages.set(root, { untrusted: 'none', sensitive: 'none' })
    if (!seen && !(req.fresh && root === req.session)) this.raise(req.session, 'unknown_session')
    return { version: VERSION, legs: { ...this.lineages.get(root)! } }
  }

  private screenAnswer(req: Requests['screen']): Responses['screen'] | { error: Code } {
    if (this.screen === 'unavailable') {
      this.raise(req.session, req.source)
      return { error: 'unavailable' }
    }
    const { decision, scores } =
      typeof this.screen === 'function'
        ? this.screen(req)
        : {
            decision: (req.scores.injection >= DENY_AT
              ? 'deny'
              : Math.max(req.scores.injection, req.scores.credentials, req.scores.exfiltration) >= TAINT_AT
                ? 'escalate'
                : 'pass') as ScreenDecision,
            scores: req.scores,
          }
    if (decision !== 'pass') this.raise(req.session, req.source)
    if (scores.credentials >= TAINT_AT) this.raise(req.session, 'credential')
    return { version: VERSION, decision, scores, gap: 'none', legs: { ...this.legsOf(req.session)! } }
  }
}
