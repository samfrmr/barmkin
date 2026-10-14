import { expect, test } from 'claude-code/testing'
import {
  CLASSIFIER_WINDOW_OVERLAP,
  MAX_CLASSIFIER_WINDOWS,
  planWindows,
} from '../hooks/lib/classifier-windows'
import { CLASSIFIER_WINDOW_CHARS } from '../hooks/lib/taint'
import { MAX_WINDOWS, MAX_WINDOW_SIZE } from '../hooks/lib/proto.ts'

const prose = (length: number) => {
  let out = ''
  for (let i = 0; out.length < length; i++) out += 'word' + i + ' '
  return out.slice(0, length)
}
const run = (length: number) => 'a'.repeat(length)

test('the plan is five windows of 4,000 characters overlapping by 512', () => {
  expect(CLASSIFIER_WINDOW_CHARS).toBe(4000)
  expect(CLASSIFIER_WINDOW_OVERLAP).toBe(512)
  expect(MAX_CLASSIFIER_WINDOWS).toBe(5)
})

test('window counts at the plan\'s edges', () => {
  const count = (n: number) => planWindows(run(n)).windows.length
  expect(count(0)).toBe(1)
  expect(count(1)).toBe(1)
  expect(count(4000)).toBe(1)
  expect(count(4001)).toBe(2)
  expect(count(7488)).toBe(2)
  expect(count(7489)).toBe(3)
  expect(count(10976)).toBe(3)
  expect(count(10977)).toBe(4)
  expect(count(14464)).toBe(4)
  expect(count(14465)).toBe(5)
  expect(count(16384)).toBe(5)
  expect(count(17952)).toBe(5)
})

test('five windows cover the 16 KiB limit; past the cap the rest is left unclassified', () => {
  const full = planWindows(run(17952))
  expect(full.covered).toBe(17952)
  const over = planWindows(run(17953))
  expect(over.windows).toHaveLength(5)
  expect(over.covered).toBe(17952)
  expect(17953 - over.covered).toBe(1)
})

test('the plan fits the contract: at most MAX_WINDOWS windows of at most MAX_WINDOW_SIZE, none empty', () => {
  expect(MAX_CLASSIFIER_WINDOWS).toBe(MAX_WINDOWS)
  expect(CLASSIFIER_WINDOW_CHARS).toBe(MAX_WINDOW_SIZE)
  for (const text of [prose(1), prose(4000), prose(4001), run(16384), run(40000)]) {
    const { windows } = planWindows(text)
    expect(windows.length).toBeGreaterThan(0)
    expect(windows.length).toBeLessThanOrEqual(MAX_WINDOWS)
    for (const w of windows) {
      expect(w.end - w.start).toBeGreaterThan(0)
      expect(w.end - w.start).toBeLessThanOrEqual(MAX_WINDOW_SIZE)
    }
  }
})

test('every window is at most 4,000 characters and consecutive windows overlap by at least 512', () => {
  for (const text of [prose(9000), run(9000), prose(16384), run(16384)]) {
    const { windows } = planWindows(text)
    for (const w of windows) expect(w.end - w.start).toBeLessThanOrEqual(4000)
    for (let i = 1; i < windows.length; i++) {
      expect(windows[i - 1].end - windows[i].start).toBeGreaterThanOrEqual(CLASSIFIER_WINDOW_OVERLAP)
      expect(windows[i].start).toBeGreaterThan(windows[i - 1].start)
    }
    expect(windows[0].start).toBe(0)
    expect(windows[windows.length - 1].end).toBe(text.length)
  }
})

test('any stretch of up to the overlap lies whole inside some window, at every offset', () => {
  const text = prose(16384)
  const { windows } = planWindows(text)
  for (let offset = 0; offset + CLASSIFIER_WINDOW_OVERLAP <= text.length; offset += 7) {
    const end = offset + CLASSIFIER_WINDOW_OVERLAP
    expect(windows.some((w) => w.start <= offset && w.end >= end)).toBe(true)
  }
})

test('a phrase straddling a window boundary is whole in some window', () => {
  const phrase = 'ignore previous instructions'
  const base = prose(16000)
  const { windows } = planWindows(base)
  for (const w of windows.slice(0, -1)) {
    for (let delta = -4; delta <= 4; delta++) {
      const at = w.end + delta - 10
      const text = base.slice(0, at) + phrase + base.slice(at + phrase.length)
      const plan = planWindows(text)
      expect(plan.windows.some((p) => text.slice(p.start, p.end).includes(phrase))).toBe(true)
    }
  }
})

test('a cut lands after whitespace when there is some nearby', () => {
  const { windows } = planWindows(prose(9000))
  for (const w of windows.slice(0, -1)) expect(/\s/.test(prose(9000)[w.end - 1])).toBe(true)
})

test('a window edge never splits a redaction placeholder', () => {
  const marker = '[REDACTED:github-token#12]'
  for (let offset = 3950; offset <= 4010; offset++) {
    const text = run(offset) + marker + run(6000)
    const { windows } = planWindows(text)
    const start = text.indexOf(marker)
    const end = start + marker.length
    for (const w of windows) {
      for (const edge of [w.start, w.end]) expect(edge > start && edge < end).toBe(false)
    }
    expect(windows.some((w) => w.start <= start && w.end >= end)).toBe(true)
  }
})

test('a window edge never splits a surrogate pair', () => {
  const emoji = '\u{1F600}'
  for (let offset = 3995; offset <= 4005; offset++) {
    const text = run(offset) + emoji.repeat(2000)
    for (const w of planWindows(text).windows) {
      for (const edge of [w.start, w.end]) {
        if (edge > 0 && edge < text.length) {
          const code = text.charCodeAt(edge - 1)
          expect(code >= 0xd800 && code <= 0xdbff).toBe(false)
          const next = text.charCodeAt(edge)
          expect(next >= 0xdc00 && next <= 0xdfff).toBe(false)
        }
      }
    }
  }
})
