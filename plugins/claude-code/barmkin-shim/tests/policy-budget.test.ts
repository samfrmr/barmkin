import { expect, test } from 'claude-code/testing'
import { MAX_LIST_COST, checkPattern, parsePolicy } from '../hooks/lib/policy'
import { redactInEitherView } from '../hooks/lib/redaction'
import { scrubInvisible } from '../hooks/lib/scrub'
import { worstInputs } from './fuzz-support'

// What the root policy's pattern bounds cost (hooks/lib/policy.ts). Each
// redaction list here is as costly as the bounds allow, and each input is built
// to make its patterns backtrack. With the built-in rules, both redaction passes
// and the scrub must stay inside redaction-budget.test.ts's 800 ms per MiB; the
// best of three runs keeps a busy machine from failing the test.
const CAP = 256 * 1024
const BUDGET_MS_PER_MIB = 800

function redactionList(patterns: string[], examples: string[]): string {
  return (
    'version: 1\nredaction:\n' +
    patterns.map((p, i) => '  - name: r' + i + '\n    category: r' + i + "\n    pattern: '" + p + "'\n    example: '" + examples[i] + "'\n").join('')
  )
}

const ALTERNATION = '(?:aa|ab)(?:aa|ab)(?:aa|ab)(?:aa|ab)X'

// Each list sums to MAX_LIST_COST.
const LISTS: Record<string, { text: string; input: string }> = {
  'two backtracking ranges': {
    text: redactionList(['[a-z]{0,15}X', '[a-y]{0,15}X'], ['aX', 'aX']),
    input: 'a'.repeat(16) + '!X',
  },
  'two 255-character runs': {
    text: redactionList(['[a-z]{255}X', '[a-y]{255}X'], ['a'.repeat(255) + 'X', 'a'.repeat(255) + 'X']),
    input: 'a'.repeat(254) + 'X',
  },
  'a run, a range and an alternation': {
    text: redactionList(['[a-z]{207}X', 'a[a-z]{0,7}[0-9]{0,1}X', ALTERNATION], ['a'.repeat(207) + 'X', 'aX', 'aaaaaaaaX']),
    input: 'aaaaaaaa9!' + 'ab'.repeat(5) + '!',
  },
}

function fill(unit: string, length: number): string {
  return unit.repeat(Math.ceil(length / unit.length)).slice(0, length)
}

test('each budget list is at the list bound', () => {
  expect(checkPattern('[a-z]{0,15}X') * 2).toBe(MAX_LIST_COST)
  expect(checkPattern('[a-z]{255}X') * 2).toBe(MAX_LIST_COST)
  expect(checkPattern('[a-z]{207}X') + checkPattern('a[a-z]{0,7}[0-9]{0,1}X') + checkPattern(ALTERNATION)).toBe(MAX_LIST_COST)
})

for (const [name, list] of Object.entries(LISTS)) {
  const rules = parsePolicy(list.text).redactionRules
  const inputs: Record<string, string> = { 'its own worst input': fill(list.input, 1024 * 1024), ...worstInputs(1024 * 1024) }
  for (const label of Object.keys(inputs)) {
    test('a policy with ' + name + ' stays within 800 ms per MiB on ' + label, () => {
      const text = inputs[label]
      let best = Infinity
      for (let run = 0; run < 3; run++) {
        const started = performance.now()
        for (let at = 0; at < text.length; at += CAP) {
          const chunk = text.slice(at, at + CAP)
          scrubInvisible(chunk)
          redactInEitherView(chunk, rules, {})
        }
        best = Math.min(best, performance.now() - started)
      }
      if (best > BUDGET_MS_PER_MIB) throw new Error(name + ' on ' + label + ' took ' + best.toFixed(0) + ' ms per MiB')
    })
  }
}
