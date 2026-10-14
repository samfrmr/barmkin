import { expect, test } from 'claude-code/testing'
import { runFuzz } from './prefix-fuzz-support'

// 16 batches of 250 trials: every test stays well inside the default test time
// on a slow runner, and each fuzz file runs in its own process, in parallel with
// the others. Together the three files run 12,000 trials.
for (let batch = 0; batch < 16; batch++) {
  test('fuzz, multi-line, batch ' + batch + ': 250 trials, a secret across the 12 KiB mark in about half, leak nothing', () => {
    const stats = runFuzz(42 * 1000 + batch, 250, false)
    expect(stats.trials).toBe(250)
    expect(stats.straddling).toBeGreaterThan(100)
    expect(stats.leaks).toBe(0)
    // The control must leak, or the corpus is not testing the cut.
    expect(stats.naiveLeaks).toBeGreaterThan(10)
    expect(stats.withheld).toBe(0)
  })
}
