// The OpenCode shim's client for the barmkin monitor contract
// (shims/common/proto.ts, the TypeScript mirror of internal/proto). Each
// request is one HTTP POST over the monitor's Unix socket with Bun's
// `fetch(url, { unix })`, bounded by its own deadline: OpenCode puts no
// timeout on a plugin hook, so a hung monitor would otherwise stall the
// session. Every reply is decoded strictly, and anything other than a
// well-formed answer of the operation's own shape is a failure. A failure
// always denies the step it guards.

import {
  CLIENT_DEADLINE_MS,
  HTTP_STATUS,
  ProtoError,
  decodeError,
  decodeResponse,
  encodeRequest,
  opPath,
  type Code,
  type Legs,
  type Op,
  type Requests,
  type Responses,
} from '../../common/proto.ts'

// How long one request may take, end to end, body included.
export const REQUEST_DEADLINE_MS = CLIENT_DEADLINE_MS

// The environment variable naming the monitor's Unix socket.
export const SOCKET_ENV = 'BARMKIN_MONITOR_SOCKET'

// Same opaque token shape the monitor accepts for sessions and roots.
export const TOKEN = /^[A-Za-z0-9._-]{1,128}$/

// Why a request failed: one of the contract's codes, or a failure on the
// shim's own side (no socket configured, or no answer within the deadline).
export type Failure = Code | 'not_configured' | 'timeout'

export type Answer<O extends Op> = { ok: true; value: Responses[O] } | { ok: false; failure: Failure }

// The URL a request is posted to. Over a Unix socket the host is ignored.
export function monitorUrl(op: Op): string {
  return 'http://barmkin' + opPath(op)
}

// interpretReply reads one HTTP reply. A 200 must carry the operation's
// response; any other status must carry an error whose code maps to that
// status. A reply from another protocol version is a version mismatch; any
// other malformed reply is a failure to read the monitor, so unavailable.
export function interpretReply<O extends Op>(op: O, status: number, text: string): Answer<O> {
  try {
    if (status === 200) return { ok: true, value: decodeResponse(op, text) }
    const { error } = decodeError(text)
    return { ok: false, failure: HTTP_STATUS[error] === status ? error : 'unavailable' }
  } catch (err) {
    return { ok: false, failure: err instanceof ProtoError && err.code === 'version_mismatch' ? 'version_mismatch' : 'unavailable' }
  }
}

// The legs a successful answer carries, if its operation reports them.
export function answerLegs(value: unknown): Legs | null {
  if (!value || typeof value !== 'object' || !('legs' in value)) return null
  return (value as { legs: Legs }).legs
}

// Posts one request to the monitor at socketPath. Never throws: a refused
// connection, a deadline, a request the contract refuses to encode and a
// malformed reply are all failures.
export async function postMonitor<O extends Op>(
  socketPath: string,
  op: O,
  request: Requests[O],
  deadlineMs: number = REQUEST_DEADLINE_MS,
): Promise<Answer<O>> {
  if (socketPath === '') return { ok: false, failure: 'not_configured' }
  let body: string
  try {
    body = encodeRequest(op, request)
  } catch {
    return { ok: false, failure: 'bad_request' }
  }
  const signal = AbortSignal.timeout(deadlineMs)
  try {
    const response = await fetch(monitorUrl(op), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
      unix: socketPath,
      signal,
    } as RequestInit)
    return interpretReply(op, response.status, await response.text())
  } catch {
    return { ok: false, failure: signal.aborted ? 'timeout' : 'unavailable' }
  }
}

// What a failure tells the person and the model.
export function describeFailure(failure: Failure): string {
  switch (failure) {
    case 'not_configured':
      return 'the barmkin monitor socket is not configured (' + SOCKET_ENV + ' is not set)'
    case 'timeout':
      return 'the barmkin monitor did not answer within ' + REQUEST_DEADLINE_MS + ' ms'
    case 'unavailable':
      return 'the barmkin monitor is not reachable or cannot answer safely right now'
    case 'version_mismatch':
      return 'the barmkin monitor speaks another protocol version; upgrade the shim and the monitor together'
    case 'unknown_session':
      return 'the barmkin monitor does not know this session'
    case 'posture_refused':
      return (
        "the barmkin monitor refused this session's posture: OpenCode runs its tools outside a sandbox, so they could reach the monitor's socket. " +
        'Run OpenCode inside an OS sandbox whose tools cannot reach the socket, and set the sandboxed option'
      )
    case 'bad_request':
      return "the barmkin monitor rejected the shim's request"
  }
}
