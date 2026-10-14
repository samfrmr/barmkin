import { test } from 'claude-code/testing'
import { REDACTION_RULES } from '../hooks/lib/redaction-rules'
import { redactInEitherView } from '../hooks/lib/redaction'
import { scrubInvisible } from '../hooks/lib/scrub'
import { worstInputs } from './fuzz-support'

// The cost the outermost redaction hook adds per string: the invisible-text
// count (a scrub) and the two-pass redaction. At the 256 KiB per-string cap a
// MiB of text is four strings. The budget is 800 ms per MiB, a tenth of what
// the hook's 10 s allows for a worst-case 1.25 MiB result; the measured worst
// case is well under it, and the best of three runs keeps a busy machine from
// failing the test.
const CAP = 256 * 1024
const BUDGET_MS_PER_MIB = 800

function hookWork(text: string): void {
  for (let at = 0; at < text.length; at += CAP) {
    const chunk = text.slice(at, at + CAP)
    scrubInvisible(chunk)
    redactInEitherView(chunk, REDACTION_RULES, {})
  }
}

// One test per input, so a slow runner spends its time budget a case at a time.
for (const label of Object.keys(worstInputs(4096))) {
  test('both redaction passes and the scrub cost at most 800 ms per MiB on ' + label, () => {
    const text = worstInputs(1024 * 1024)[label]
    let best = Infinity
    for (let run = 0; run < 3; run++) {
      const started = performance.now()
      hookWork(text)
      best = Math.min(best, performance.now() - started)
    }
    if (best > BUDGET_MS_PER_MIB) throw new Error(label + ' took ' + best.toFixed(0) + ' ms per MiB')
  })
}
