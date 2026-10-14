// Host-neutral wrappers the OpenCode adapter imports to read, annotate, withhold
// and redact a tool result. The Claude-side helpers in the shared tool-result.ts
// are reused, not copied: `extractResultText` does the text extraction. The
// other two (`appendContext`, `withholdResult`) encode Claude's result schema
// (a sibling `context` array; typed-record variants that must stay valid for
// each tool's output schema) and have no 2.x counterpart: on 2.x the model
// reads `content`, and an after-hook may replace the whole result with a plain
// string `output` (V20). The 2.x equivalents live here.
//
// Shapes and the checks that back them are documented in ./result-shapes.

import { extractResultText } from './lib'
import {
  isToolAfterCompleted,
  isToolAfterError,
  mapErrorStrings,
  mapResultStrings,
  type StringMap,
  type ToolAfterEvent,
  type ToolContentPart,
  type ToolError,
  type ToolResult,
} from './result-shapes'

// The value of a structured `output`, as the text a screen should read. Shell,
// webfetch, MCP, skill and Code Mode all nest the payload as a string under an
// `output` key (V20, V24, V31, V33); anything else is stringified by the
// shared extractor.
function outputText(output: unknown, depth = 0): string {
  if (typeof output === 'string') return output
  if (output && typeof output === 'object' && !Array.isArray(output) && depth < 4) {
    const rec = output as Record<string, unknown>
    const inner = rec.output
    if (typeof inner === 'string' || (inner && typeof inner === 'object')) {
      const head = typeof inner === 'string' ? inner : outputText(inner, depth + 1)
      const siblings = Object.keys(rec).filter((k) => k !== 'output' && typeof rec[k] === 'string').map((k) => rec[k] as string)
      return [head, ...siblings].join('\n')
    }
  }
  return extractResultText({ result: output })
}

// Everything the model or the store keeps from a result: `content` text parts
// (what the model reads) plus the structured `output`, de-duplicated when the
// output text is already inside the content. Screens see at least what the
// model sees.
export function toolResultText(result: ToolResult | null | undefined): string {
  if (!result || typeof result !== 'object') return ''
  const content = extractResultText({ result: result.content })
  const output = result.output === undefined ? '' : outputText(result.output)
  if (!output) return content
  if (!content) return output
  return content.includes(output) ? content : output.includes(content) ? output : content + '\n' + output
}

export function toolErrorText(error: ToolError | null | undefined): string {
  return error && typeof error.message === 'string' ? error.message : ''
}

// The text of an execute.after event, success or error (V21).
export function afterEventText(event: ToolAfterEvent): string {
  if (isToolAfterCompleted(event)) return toolResultText(event.result)
  if (isToolAfterError(event)) return toolErrorText(event.error)
  return ''
}

function contentParts(content: ToolResult['content']): ToolContentPart[] {
  if (typeof content === 'string') return content ? [{ type: 'text', text: content }] : []
  return Array.isArray(content) ? [...content] : []
}

// The result with `text` appended as one more text part. A result with only a
// structured `output` and no `content` keeps its output text as the first part,
// so the notice never becomes the only thing the model reads.
export function appendNotice(result: ToolResult, text: string): ToolResult {
  const parts = contentParts(result.content)
  if (parts.length === 0 && result.output !== undefined) {
    const out = outputText(result.output)
    if (out) parts.push({ type: 'text', text: out })
  }
  return { ...result, content: [...parts, { type: 'text', text }] }
}

// A result with the payload gone: a plain string `output` and a single text
// part. Plain-string replacement is accepted by 2.x (V20, `replace` mode).
// File parts (images, PDFs) are dropped with the rest, and `metadata` is not
// carried: it can echo the withheld payload (Code Mode `toolCalls`, V24).
export function withholdToolResult(message: string): ToolResult {
  return { output: message, content: [{ type: 'text', text: message }], metadata: { barmkinWithheld: true } }
}

export function redactToolResult(result: ToolResult, fn: StringMap): ToolResult {
  return mapResultStrings(result, fn)
}

// ---------------------------------------------------------------------------
// In-place application on an execute.after event. Each returns whether it
// changed anything. A completed result is replaced wholesale on the event; an
// error is edited in place, because only `error.message` assignment is
// lab-verified (V21) and the Tool.Error class must not be rebuilt.
// ---------------------------------------------------------------------------

export function redactAfterEvent(event: ToolAfterEvent, fn: StringMap): boolean {
  if (isToolAfterCompleted(event)) {
    let changed = false
    const next = mapResultStrings(event.result, (s) => {
      const out = fn(s)
      if (out !== s) changed = true
      return out
    })
    if (changed) event.result = next
    return changed
  }
  if (isToolAfterError(event)) return mapErrorStrings(event.error, fn)
  return false
}

export function withholdAfterEvent(event: ToolAfterEvent, message: string): boolean {
  if (isToolAfterCompleted(event)) {
    event.result = withholdToolResult(message)
    return true
  }
  if (isToolAfterError(event)) {
    try {
      event.error.message = message
      return true
    } catch {
      return false
    }
  }
  return false
}

export function noticeAfterEvent(event: ToolAfterEvent, text: string): boolean {
  if (isToolAfterCompleted(event)) {
    event.result = appendNotice(event.result, text)
    return true
  }
  if (isToolAfterError(event)) {
    try {
      event.error.message = toolErrorText(event.error) + '\n\n' + text
      return true
    } catch {
      return false
    }
  }
  return false
}
