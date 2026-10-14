// Pure helper: strips invisible-Unicode, bidi-override and ANSI/VT escape
// characters that can hide an instruction or smuggle data past a human or a
// naive text scanner (OWASP LLM01:2026 mitigation #5; LLM10:2026 risk
// example #6; "Trojan Source", CVE-2021-42574). No `$` use here: imported
// into register.ts and redaction.ts, whose hooks call it on tool results, MCP
// descriptions, peer messages, and the prompt.submit and session.send checks.

// Full ANSI/VT escape sequences, not just the bare ESC byte: CSI (`ESC [
// ... final-byte`), OSC (`ESC ] ... BEL` or `... ESC \`), and the shorter
// two-byte Fe-class escapes. Stripping only the ESC byte would leave the
// parameter/terminator bytes behind as inert but visible garbage; this
// removes the whole sequence.
const ANSI_ESCAPE = /\x1B(?:\[[0-?]*[ -\/]*[@-~]|\][^\x07\x1B]*(?:\x07|\x1B\\)|[@-Z\\-_])/g

// The Unicode Tags block (U+E0000-E007F): invisible by design, used to hide
// a full instruction string behind a visible emoji or character.
const TAG_BLOCK = /[\u{E0000}-\u{E007F}]/gu

// Bidi override and isolate controls: no legitimate reason for fetched
// text, a tool result or a peer message to contain these.
const BIDI_CONTROLS = /[‪-‮⁦-⁩]/g

// C0 controls except \t \n \r, and C1 controls. This also removes a bare
// ESC byte left over from anything ANSI_ESCAPE didn't match as a full
// sequence.
const C0_C1_CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g

// Zero-width characters used to split a token so a naive scanner's pattern
// doesn't match it, or to hide a marker mid-text. U+FEFF (BOM) is only
// stripped mid-text; a BOM at the very start of the input is a legitimate
// encoding marker and is left alone (handled separately in scrubInvisible).
const ZERO_WIDTH = /[​-‍⁠﻿]/g

// ZWNJ (U+200C) and ZWJ (U+200D) are still stripped, but are ordinary
// spelling in Persian and Indic scripts and glue ZWJ emoji sequences, so
// they don't count toward `hiddenCount`.
const JOINERS = new Set(['‌', '‍'])

// A lone or paired variation selector (U+FE00-FE0F, plus the supplementary
// Variation Selectors Supplement U+E0100-E01EF) is ordinary text: VS16 sets
// emoji presentation, VS1-16 distinguish CJK ideograph variants, and
// keycap emoji (`1️⃣`) use exactly one. A *run* of four or more in
// a row has no such use -- it's the steganographic encoding some
// invisible-prompt-injection demos use (one selector per smuggled byte) --
// so only runs at or above that length are stripped. This run-length rule is
// an intentional tradeoff, not a stripping of every selector outside an emoji
// sequence: a single selector after each
// visible character (one smuggled byte per character, every run only one
// long) stays under this threshold and is not stripped.
const VARIATION_SELECTOR_RUN = /[︀-️\u{E0100}-\u{E01EF}]{4,}/gu

// `strippedCount` counts everything removed. `hiddenCount` leaves out ANSI
// escapes and C0/C1 controls: terminal formatting in colored tool output is
// routine, so only the invisible-text carriers (tags, bidi, zero-width
// other than ZWNJ/ZWJ, variation-selector runs) count toward the
// steganographic signal.
export interface ScrubResult {
  text: string
  strippedCount: number
  hiddenCount: number
}

export function scrubInvisible(text: string): ScrubResult {
  let strippedCount = 0
  let hiddenCount = 0
  const hasLeadingBom = text.startsWith('﻿')
  let body = hasLeadingBom ? text.slice(1) : text

  body = body.replace(ANSI_ESCAPE, () => {
    strippedCount++
    return ''
  })
  body = body.replace(TAG_BLOCK, () => {
    strippedCount++
    hiddenCount++
    return ''
  })
  body = body.replace(BIDI_CONTROLS, () => {
    strippedCount++
    hiddenCount++
    return ''
  })
  body = body.replace(C0_C1_CONTROLS, () => {
    strippedCount++
    return ''
  })
  body = body.replace(ZERO_WIDTH, (ch) => {
    strippedCount++
    if (!JOINERS.has(ch)) hiddenCount++
    return ''
  })
  body = body.replace(VARIATION_SELECTOR_RUN, (run) => {
    strippedCount += [...run].length
    hiddenCount += [...run].length
    return ''
  })

  return { text: hasLeadingBom ? '﻿' + body : body, strippedCount, hiddenCount }
}
