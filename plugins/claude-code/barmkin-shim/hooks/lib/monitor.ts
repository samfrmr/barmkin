// The shim's side of the barmkin monitor contract (proto.ts), without `$`:
// register.ts sends each request with $.http.fetch over the monitor's Unix
// socket, and reads the reply through interpretReply. Every reply is decoded
// strictly; anything other than a well-formed answer of the operation's own
// shape is a failure, and a failure always denies the guarded step.

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
} from './proto.ts'

// How long one request may take, end to end. A request that has not answered
// by then is a failure: $.http.fetch has no timeout of its own.
export const REQUEST_DEADLINE_MS = CLIENT_DEADLINE_MS

// The environment variable naming the monitor's Unix socket.
export const SOCKET_ENV = 'BARMKIN_MONITOR_SOCKET'

// Same opaque token shape the monitor accepts for sessions and calls.
export const TOKEN = /^[A-Za-z0-9._-]{1,128}$/

// Why a request failed: one of the contract's codes, or a failure on the
// shim's own side (no socket configured, or no answer within the deadline).
export type Failure = Code | 'not_configured' | 'timeout'

export type Answer<O extends Op> = { ok: true; value: Responses[O] } | { ok: false; failure: Failure }

// The URL a request is posted to. Over a Unix socket the host is ignored.
export function monitorUrl(op: Op): string {
  return 'http://barmkin' + opPath(op)
}

// encodeBody encodes a request, or returns null for one the contract refuses
// (a malformed token, say), which is then never sent.
export function encodeBody<O extends Op>(op: O, request: Requests[O]): string | null {
  try {
    return encodeRequest(op, request)
  } catch {
    return null
  }
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
      return "the barmkin monitor refused this session's posture: tools must run in the sandbox, without allowAllUnixSockets"
    case 'bad_request':
      return "the barmkin monitor rejected the shim's request"
  }
}
