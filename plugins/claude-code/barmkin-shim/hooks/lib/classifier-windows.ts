// How redacted untrusted content is cut into the classifier's windows. Pure:
// register.ts sends the windows to the barmkin monitor, whose screen service
// scores them (internal/screen/windows.go is the Go port of this file). The
// text handed in is already redacted (classifierInput), so a cut never splits a
// secret, only at worst a placeholder, which planWindows avoids.
import { CLASSIFIER_WINDOW_CHARS } from './taint'

// Consecutive windows share this many characters, so any stretch of text this
// long or shorter lies whole inside at least one window. The longest match of
// any injection heuristic is 178 characters (the AI-addressed notice), and the
// longest redaction placeholder is 34.
export const CLASSIFIER_WINDOW_OVERLAP = 512

// Five windows cover 4,000 + 4 x 3,488 = 17,952 characters: the 16 KiB limit
// of the screened surfaces, plus room for placeholders longer than what they
// replaced. Text past the last window is never classified.
export const MAX_CLASSIFIER_WINDOWS = 5

// A window's end moves back by at most this many characters to land after
// whitespace rather than inside a word.
const BOUNDARY_SLACK = 128

const PLACEHOLDER = /\[REDACTED:[a-z-]+#\d+\]/y
const PLACEHOLDER_MAX = 48

export interface ClassifierWindow {
  start: number
  end: number
}

// Moves a cut back so it falls after whitespace when there is some nearby, and
// never inside a placeholder or between the halves of a surrogate pair.
function snapCut(text: string, cut: number): number {
  let c = cut
  for (let i = cut; i > Math.max(cut - BOUNDARY_SLACK, 0); i--) {
    if (/\s/.test(text[i - 1])) {
      c = i
      break
    }
  }
  const open = text.lastIndexOf('[REDACTED:', c - 1)
  if (open !== -1 && open > c - PLACEHOLDER_MAX) {
    PLACEHOLDER.lastIndex = open
    const m = PLACEHOLDER.exec(text)
    if (m && open + m[0].length > c) c = open
  }
  const code = text.charCodeAt(c - 1)
  if (code >= 0xd800 && code <= 0xdbff) c--
  return c
}

// Moves a window's start back so it does not begin inside a placeholder or on
// the second half of a surrogate pair; the overlap only grows.
function snapStart(text: string, start: number): number {
  let s = start
  const open = text.lastIndexOf('[REDACTED:', s)
  if (open !== -1 && open > s - PLACEHOLDER_MAX) {
    PLACEHOLDER.lastIndex = open
    const m = PLACEHOLDER.exec(text)
    if (m && open + m[0].length > s) s = open
  }
  const code = text.charCodeAt(s)
  if (code >= 0xdc00 && code <= 0xdfff) s--
  return s
}

// Windows of at most `size` characters, each starting `overlap` characters
// before the previous one ended, from the start of the text until it is
// covered or `max` windows are planned. `covered` is where the last ends.
export function planWindows(
  text: string,
  size = CLASSIFIER_WINDOW_CHARS,
  overlap = CLASSIFIER_WINDOW_OVERLAP,
  max = MAX_CLASSIFIER_WINDOWS,
): { windows: ClassifierWindow[]; covered: number } {
  const windows: ClassifierWindow[] = []
  let start = 0
  while (windows.length < max) {
    const end = start + size >= text.length ? text.length : snapCut(text, start + size)
    windows.push({ start, end })
    if (end >= text.length) break
    start = Math.max(snapStart(text, end - overlap), start + 1)
  }
  return { windows, covered: windows.length === 0 ? 0 : windows[windows.length - 1].end }
}
