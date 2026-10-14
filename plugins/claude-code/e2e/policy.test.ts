// End-to-end tests of the root policy (/etc/barmkin/policy.yaml) on the Claude
// Code path: the real shim hooks module, a real `barmkin monitor` and the real
// managed `barmkin gate`, with the policy file as $.fs answers it (host.ts).
// The policy only adds: its outward command reaches the monitor's decide as
// shell-outward, and its secret path raises the sensitive leg. An invalid
// policy sends the monitor nothing, so the gate denies every call.

import { describe, test, type TestContext } from 'node:test'
import assert from 'node:assert/strict'
import { interpretReply } from '../barmkin-shim/hooks/lib/monitor.ts'
import { VERSION, type Legs } from '../barmkin-shim/hooks/lib/proto.ts'
import { ACME_UPLOAD, FULL_POLICY, VAULT_PATH } from '../barmkin-shim/tests/support/policy-fixtures.ts'
import { ClaudeCode, type LaunchOptions } from './host.ts'
import { Monitor } from './monitor.ts'

async function monitor(t: TestContext): Promise<Monitor> {
  const m = await Monitor.start()
  t.after(() => m.close())
  return m
}

function launch(m: Monitor, opts: Partial<LaunchOptions> = {}): Promise<ClaudeCode> {
  return ClaudeCode.launch({ socket: m.socket, ...opts })
}

async function legs(m: Monitor, session: string): Promise<Legs | string> {
  const r = await m.send('status', JSON.stringify({ version: VERSION, host: 'claude_code', session }))
  const answer = interpretReply('status', r.status, r.text)
  return answer.ok ? answer.value.legs : answer.failure
}

// The monitor core has no classifier: its screen raises the untrusted leg for
// any fetched page and answers unavailable, so the shim withholds the page.
async function taint(cc: ClaudeCode): Promise<void> {
  const fetched = await cc.use('WebFetch', { url: 'https://example.com/', prompt: 'summarise' }, 'page text')
  assert.equal(fetched.gate.code, 0, fetched.gate.stderr)
}

describe('the root policy', () => {
  test("a policy's outward command is denied by the monitor once the session is tainted", async (t) => {
    const m = await monitor(t)
    const cc = await launch(m, { policy: FULL_POLICY })
    await taint(cc)
    const use = await cc.use('Bash', { command: ACME_UPLOAD })
    assert.equal(use.gate.code, 0, use.gate.stderr)
    assert.equal(use.ran, false, 'the command ran')
    assert.match(use.out.deny, /outward-effect shell command/)
  })

  test('without the policy, the same command is not an egress class and runs while tainted', async (t) => {
    const m = await monitor(t)
    const cc = await launch(m)
    await taint(cc)
    const use = await cc.use('Bash', { command: ACME_UPLOAD })
    assert.equal(use.gate.code, 0, use.gate.stderr)
    assert.equal(use.ran, true)
  })

  test("a policy's secret path raises the sensitive leg in the monitor", async (t) => {
    const m = await monitor(t)
    const cc = await launch(m, { policy: FULL_POLICY })
    const use = await cc.use('Bash', { command: 'cat ' + VAULT_PATH })
    assert.equal(use.ran, true)
    assert.deepEqual(await legs(m, cc.sessionId), { untrusted: 'none', sensitive: 'credential' })
  })

  test('an invalid policy registers no session, so the gate denies every call', async (t) => {
    const m = await monitor(t)
    const cc = await launch(m, { policy: 'version: 1\nclear_taint: true\n' })
    for (const [tool, input] of [
      ['Bash', { command: 'ls' }],
      ['Read', { file_path: '/proj/README.md' }],
    ] as const) {
      const use = await cc.use(tool, input)
      assert.deepEqual([use.gate.code, use.gate.reason], [2, 'unknown-session'], use.gate.stderr)
      assert.equal(use.ran, false, tool + ' ran')
    }
    assert.equal(await legs(m, cc.sessionId), 'unknown_session')
    assert.ok(cc.logs.some((l) => l.includes('the root policy /etc/barmkin/policy.yaml is invalid (line 2: unknown key "clear_taint"')), cc.logs.join('\n'))
  })
})
