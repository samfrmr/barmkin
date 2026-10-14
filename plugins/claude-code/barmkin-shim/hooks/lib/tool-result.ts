// Pure helpers for reading and annotating a tool.call result. Tool results
// vary by tool: usually a string, sometimes a structured content-block
// array (MCP tools in particular). This extracts the best-effort text
// without assuming one shape. The full text is returned so the local
// screens see everything Claude will; only the classifier payload is capped.

export function extractResultText(result: unknown): string {
  if (result === null || result === undefined) return ''
  const r = result as { result?: unknown }
  const value = 'result' in (result as object) ? r.result : result
  if (typeof value === 'string') return value
  if (Array.isArray(value)) {
    const text = value
      .map((block) => (block && typeof block === 'object' && typeof (block as { text?: unknown }).text === 'string' ? (block as { text: string }).text : ''))
      .filter(Boolean)
      .join('\n')
    if (text) return text
  }
  if (typeof value === 'object' && value !== null) {
    try {
      return JSON.stringify(value)
    } catch {
      return ''
    }
  }
  return ''
}

export function appendContext<T extends { context?: unknown }>(result: T, text: string): T & { context: unknown[] } {
  const existing = Array.isArray(result?.context) ? result.context : []
  return { ...result, context: [...existing, text] }
}

// Withholds a tool result's content while keeping it in-schema for that
// tool. A plain-string result or an MCP tool's result (string or
// content-block array both validate against its looser schema) collapses to
// `{ result: message }`. WebFetch and WebSearch return typed records, so
// only their payload is replaced: WebFetch's `result` text, and WebSearch's
// `results` array (hits and commentary) becomes `[message]`.
// Read's result is a typed record whose output schema requires an object.
// For Read's text variant (`{ type: 'text', file: { content, ... } }`) only
// `file.content` is replaced. Read's other variants (notebook, pdf, image)
// carry their payload in `cells` / `base64`, so those are rebuilt as a
// minimal text record holding just the message, dropping the payload.
export function withholdResult(result: unknown, message: string): { result: unknown } {
  const value = result && typeof result === 'object' ? (result as { result?: unknown }).result : undefined
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    if (typeof (value as { result?: unknown }).result === 'string') return { result: { ...value, result: message } }
    if (Array.isArray((value as { results?: unknown }).results)) return { result: { ...value, results: [message] } }
  }
  if (value && typeof value === 'object' && !Array.isArray(value) && 'file' in value) {
    const { type, file } = value as { type?: unknown; file?: unknown }
    const numLines = message.split('\n').length
    if (type === 'text' && file && typeof file === 'object' && !Array.isArray(file)) {
      return { result: { ...value, file: { ...file, content: message, numLines } } }
    }
    const filePath = file && typeof (file as { filePath?: unknown }).filePath === 'string' ? (file as { filePath: string }).filePath : ''
    return {
      result: { type: 'text', file: { filePath, content: message, numLines, startLine: 1, totalLines: numLines } },
    }
  }
  return { result: message }
}
