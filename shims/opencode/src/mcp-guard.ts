// MCP tool-poisoning guard for the OpenCode 2.x host adapter (W4).
//
// Re-scout V23: a plugin's `tool.transform` sees every MCP tool with its
// description, in direct and Code Mode alike, and a rewrite there reaches the
// model. This module wires four pieces around hooks/lib/mcp-guard:
//
//   1. `mcp.transform`      drops servers that are not on the allowlist before
//                           they connect, so an unlisted server contributes no
//                           tools and no `instructions` text at all.
//   2. `tool.transform`     neutralises MCP tool descriptions (and the
//                           descriptions inside input schemas), and hides the
//                           tools of an unlisted server or a tool it could not
//                           screen. It never throws: a transform that throws
//                           disables the whole plugin mid-session (V19).
//   3. `execute.before` and `permission.evaluate` throw for a call that
//                           resolves to an unlisted server. A throw is final
//                           (V2, V7); setting `effect = "deny"` is not (V6).
//   4. `session.context`    neutralises server `instructions` in the system
//                           prompt and in the synthetic "catalog has changed"
//                           messages OpenCode injects (V23), and re-checks the
//                           tool descriptions the model is about to read.
//
// Hidden text stripped from a server's descriptions, schemas or instructions
// is a finding about that server, made before any session exists. Findings
// are keyed by a hash of the server's configuration, as the last mcp.transform
// saw it, and `findingsFor` returns only the findings for servers a session's
// request actually enumerates (its tools or instructions). So a poisoned
// server taints the sessions that use it and no other session on the
// instance, and a server whose configuration changes is judged afresh.
//
// It reaches the host through the structural types below, not through
// @opencode/plugin, so it stays free of runtime dependencies and the server
// adapter can hand it a fake host in tests. Not covered, by design: MCP tool
// arguments are invisible at permission time (V24), and the Code Mode
// catalog text is built from the registry, so it is only as clean as step 2.

import { isAllowedServer, neutralizeDescription, scrubInvisible } from './lib'

// ---------------------------------------------------------------------------
// Host shapes (the subset of the 2.x Promise plugin context this module uses)
// ---------------------------------------------------------------------------

interface RegistrationLike {
  readonly dispose: () => Promise<void>
}

export interface McpToolLike {
  readonly id: string
  readonly name: string
  description: string
  input?: unknown
  readonly options?: { readonly namespace?: string }
}

export interface ToolEditorLike {
  list(): readonly McpToolLike[]
  update(id: string, update: (tool: { description: string; input?: unknown }) => void): void
  remove(id: string): void
}

export interface McpEditorLike {
  list(): readonly (readonly [string, unknown])[]
  remove(name: string): void
}

export interface ContextTextPart {
  type?: string
  text?: string
}

export interface ContextMessage {
  role?: string
  content?: unknown
}

export interface SessionContextLike {
  system?: ContextTextPart[]
  messages?: ContextMessage[]
  tools?: Record<string, { description: string; input?: unknown }>
}

export interface McpGuardHost {
  readonly options?: Readonly<Record<string, unknown>>
  readonly mcp: {
    list(): Promise<{ readonly data: readonly { readonly name: string }[] } | readonly { readonly name: string }[]>
    transform(callback: (editor: McpEditorLike) => void): Promise<RegistrationLike>
  }
  readonly tool: {
    transform(callback: (editor: ToolEditorLike) => void): Promise<RegistrationLike>
    hook(name: 'execute.before', callback: (event: { readonly tool: string }) => void | Promise<void>): Promise<RegistrationLike>
  }
  readonly permission: {
    hook(name: 'evaluate', callback: (event: { readonly action: string }) => void | Promise<void>): Promise<RegistrationLike>
  }
  readonly session: {
    hook(name: 'context', callback: (event: SessionContextLike) => void | Promise<void>): Promise<RegistrationLike>
  }
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

// OpenCode's own registry namespace for an MCP server (core/src/tool/mcp.ts
// `namespace`). A tool is registered as `<namespace>_<tool>`.
export function mcpNamespace(server: string): string {
  return server.replace(/[^a-zA-Z0-9_-]/g, '_')
}

// JSON with every object's keys sorted, so equal configurations hash equally.
function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return '[' + value.map(canonicalJson).join(',') + ']'
  if (value !== null && typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined)
    entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    return '{' + entries.map(([k, v]) => JSON.stringify(k) + ':' + canonicalJson(v)).join(',') + '}'
  }
  return JSON.stringify(value ?? null)
}

// The key a finding about a server is kept under: a SHA-256 over its registry
// namespace and its configuration. A server whose configuration the guard
// never saw hashes with a null configuration. Only the hash is kept, so a
// credential in a server's environment never sits in the guard's state.
export function serverConfigHash(namespace: string, config: unknown): string {
  return new Bun.CryptoHasher('sha256').update(canonicalJson([namespace, config ?? null])).digest('hex')
}

// Same accepted shapes as the Claude Code adapter's `mcp_server_allowlist`:
// an array of names, or one comma-separated string.
export function parseAllowlist(raw: unknown): string[] {
  if (Array.isArray(raw)) return raw.filter((v): v is string => typeof v === 'string' && v.length > 0)
  if (typeof raw === 'string' && raw.length > 0) {
    return raw
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
  }
  return []
}

// An empty allowlist allows every server (audit-only), as on Claude Code.
// Both sides are compared as registry namespaces because that is all a tool
// id carries.
export function isServerAllowed(server: string, allowlist: readonly string[]): boolean {
  return isAllowedServer(mcpNamespace(server), allowlist.map(mcpNamespace))
}

export interface DescriptionVerdict {
  text: string
  changed: boolean
  flagged: boolean
  hiddenCount: number
}

export function screenDescription(description: string): DescriptionVerdict {
  const scrubbed = scrubInvisible(description)
  const { description: cleaned, flagged } = neutralizeDescription(scrubbed.text)
  return { text: cleaned, changed: cleaned !== description, flagged, hiddenCount: scrubbed.hiddenCount }
}

const SCHEMA_MAX_DEPTH = 24
const SCHEMA_MAX_NODES = 4000

// Neutralises every string `description` inside a JSON Schema and returns a
// rewritten copy, or null when nothing changed. Parameter descriptions reach
// the model with the tool definition, so they are as good an injection
// carrier as the top-level description.
export function screenSchema(schema: unknown): { schema: unknown; descriptions: number; flagged: number; hiddenCount: number } | null {
  let nodes = 0
  let descriptions = 0
  let flagged = 0
  let hiddenCount = 0
  const walk = (value: unknown, depth: number): unknown => {
    if (depth > SCHEMA_MAX_DEPTH || nodes++ > SCHEMA_MAX_NODES) return value
    if (Array.isArray(value)) {
      let out: unknown[] | null = null
      value.forEach((item, i) => {
        const next = walk(item, depth + 1)
        if (next !== item) (out ??= value.slice())[i] = next
      })
      return out ?? value
    }
    if (value === null || typeof value !== 'object') return value
    let out: Record<string, unknown> | null = null
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      let next: unknown
      if (key === 'description' && typeof item === 'string') {
        const verdict = screenDescription(item)
        if (verdict.flagged) flagged++
        hiddenCount += verdict.hiddenCount
        next = verdict.text
        if (verdict.changed) descriptions++
      } else {
        next = walk(item, depth + 1)
      }
      if (next !== item) (out ??= { ...(value as Record<string, unknown>) })[key] = next
    }
    return out ?? value
  }
  const rewritten = walk(schema, 0)
  return rewritten === schema ? null : { schema: rewritten, descriptions, flagged, hiddenCount }
}

const SERVER_ENTRY = /(<server name=")([^"]*)(">)([\s\S]*?)(<\/server>)/g

// The text OpenCode injects for MCP server `instructions`: a system-prompt
// block (<mcp_instructions>) and, when the set changes mid-session, a
// synthetic user-role message in one of these three shapes
// (core/src/mcp/instructions.ts).
export function isInstructionsNotice(text: string): boolean {
  return (
    text.startsWith('The available MCP server instructions have changed.') ||
    text.startsWith('New MCP server instructions are available') ||
    text.startsWith('Instructions for the following MCP servers are no longer available')
  )
}

export interface InstructionsVerdict {
  text: string
  changed: boolean
  removedServers: string[]
  neutralisedServers: string[]
  // Every listed server the block names, in order.
  servers: string[]
  flagged: number
  // Hidden-text carriers stripped from each listed server's entry.
  hiddenByServer: Record<string, number>
}

// Rewrites each <server name="…"> entry of an instructions block: an unlisted
// server's entry is removed, a listed one has its instruction text scrubbed and
// neutralised. The entries are split on the first </server>, so a server that
// forges one can only split its own text. Unlisted servers are already gone at
// source (the mcp.transform above), which is what the allowlist relies on.
export function screenInstructions(text: string, allowlist: readonly string[]): InstructionsVerdict {
  const removedServers: string[] = []
  const neutralisedServers: string[] = []
  const servers: string[] = []
  const hiddenByServer: Record<string, number> = {}
  let flagged = 0
  const rewritten = text.replace(SERVER_ENTRY, (entry, open: string, name: string, mid: string, body: string, close: string) => {
    if (!isServerAllowed(name, allowlist)) {
      removedServers.push(name)
      return ''
    }
    servers.push(name)
    const verdict = screenDescription(body)
    if (verdict.flagged) flagged++
    hiddenByServer[name] = (hiddenByServer[name] ?? 0) + verdict.hiddenCount
    if (!verdict.changed) return entry
    neutralisedServers.push(name)
    return open + name + mid + verdict.text + close
  })
  return { text: rewritten, changed: rewritten !== text, removedServers, neutralisedServers, servers, flagged, hiddenByServer }
}

// ---------------------------------------------------------------------------
// Status (plain JSON, so it can cross the status RPC unchanged)
// ---------------------------------------------------------------------------

export interface McpGuardStatus {
  installed: { mcpTransform: boolean; toolTransform: boolean; beforeHook: boolean; evaluateHook: boolean; contextHook: boolean }
  allowlist: string[]
  allowlistActive: boolean
  // Registry namespaces of the servers seen, and of those dropped at source.
  servers: string[]
  removedServers: string[]
  // Tool ids hidden from the model: unlisted server, or a tool that could not be screened.
  hiddenTools: string[]
  // Namespaces on tools that are not MCP servers the guard knows about (the
  // built-in `opencode` namespace excluded): reported, never acted on.
  unclassifiedNamespaces: string[]
  // From the last tool.transform run.
  neutralised: { descriptions: number; schemas: number; instructions: number }
  flagged: number
  // Servers with a hidden-text finding under their current configuration.
  findings: string[]
  deniedCalls: number
  lastRunAt: number | null
  errors: string[]
}

export interface McpGuardOptions {
  // Defaults to host.options.mcp_server_allowlist.
  allowlist?: unknown
  // More than this many hidden-text carriers (scrubInvisible's `hiddenCount`)
  // stripped from one piece of a server's text make a finding about it.
  hiddenTextThreshold?: number
  now?: () => number
}

// A hidden-text finding about one server, under its configuration hash.
export interface McpFinding {
  server: string
  hash: string
  reason: string
}

export interface McpGuardHandle {
  status(): McpGuardStatus
  // True when every hook registered and no screening step has errored.
  healthy(): boolean
  // The registry namespace of the MCP server that registered a tool id, if any.
  serverOf(id: string): string | undefined
  // The findings for the servers a session request enumerates: the servers of
  // its tools and the servers its instructions name. A context hook the
  // adapter registers after this guard's own sees the findings that guard
  // made on the same request.
  findingsFor(context: SessionContextLike): McpFinding[]
  // The finding for one server under its current configuration, if any.
  findingFor(server: string): McpFinding | undefined
  dispose(): Promise<void>
}

const MAX_ERRORS = 10
const BUILTIN_NAMESPACE = 'opencode'
// The scrub threshold the shims share (register.ts INVISIBLE_CHAR_TAINT_THRESHOLD).
const DEFAULT_HIDDEN_TEXT_THRESHOLD = 32
const MAX_FINDINGS = 1024

export async function installMcpGuard(host: McpGuardHost, options: McpGuardOptions = {}): Promise<McpGuardHandle> {
  const allowlist = parseAllowlist(options.allowlist ?? host.options?.mcp_server_allowlist)
  const threshold = options.hiddenTextThreshold ?? DEFAULT_HIDDEN_TEXT_THRESHOLD
  const now = options.now ?? Date.now
  const registrations: RegistrationLike[] = []
  const errors: string[] = []
  const installed = { mcpTransform: false, toolTransform: false, beforeHook: false, evaluateHook: false, contextHook: false }

  const known = new Set<string>() // registry namespaces of servers seen
  const removed = new Set<string>() // namespaces dropped at source
  const toolIndex = new Map<string, string>() // tool id -> server namespace
  const configHashes = new Map<string, string>() // namespace -> hash of its last-seen configuration
  const findings = new Map<string, McpFinding>() // configuration hash -> the first finding under it
  let hiddenTools: string[] = []
  let unclassified: string[] = []
  let lastRun = { descriptions: 0, schemas: 0, flagged: 0, at: null as number | null }
  let instructionsNeutralised = 0
  let instructionsFlagged = 0
  let deniedCalls = 0

  const fail = (where: string, error: unknown) => {
    const message = where + ': ' + (error instanceof Error ? error.message : String(error))
    if (errors.length >= MAX_ERRORS) errors.shift()
    errors.push(message)
  }
  const hashOf = (ns: string) => configHashes.get(ns) ?? serverConfigHash(ns, null)
  // Records a finding when more than the threshold of hidden-text carriers was
  // stripped from one piece of a server's text. The first finding under a
  // configuration stays.
  const hidden = (server: string, count: number, where: string) => {
    if (count <= threshold) return
    const hash = hashOf(server)
    if (findings.has(hash)) return
    if (findings.size >= MAX_FINDINGS) findings.delete(findings.keys().next().value as string)
    findings.set(hash, { server, hash, reason: 'stripped ' + count + ' invisible character(s) from ' + where + ' of MCP server "' + server + '"' })
  }

  // Resolves a tool id or permission action to the server namespace that
  // registered it: exact from the index built by the last tool.transform,
  // else the longest known namespace that prefixes it.
  const serverOf = (id: string): string | undefined => {
    const exact = toolIndex.get(id)
    if (exact !== undefined) return exact
    let best: string | undefined
    for (const ns of known) {
      if (id.startsWith(ns + '_') && (best === undefined || ns.length > best.length)) best = ns
    }
    return best
  }
  const blocked = (id: string): string | undefined => {
    const ns = serverOf(id)
    return ns !== undefined && !isServerAllowed(ns, allowlist) ? ns : undefined
  }

  const refreshServers = async () => {
    try {
      const listed = await host.mcp.list()
      const servers = Array.isArray(listed) ? listed : (listed as { data: readonly { name: string }[] }).data
      for (const server of servers) {
        const ns = mcpNamespace(server.name)
        if (ns !== BUILTIN_NAMESPACE) known.add(ns)
      }
    } catch (error) {
      fail('mcp.list', error)
    }
  }

  const register = async (key: keyof typeof installed, make: () => Promise<RegistrationLike>) => {
    try {
      registrations.push(await make())
      installed[key] = true
    } catch (error) {
      fail('install ' + key, error)
    }
  }

  await refreshServers()

  // 1. Drop unlisted servers at source. This runs after OpenCode's config MCP
  // plugin (a "pre" built-in), so config-defined servers are all visible.
  await register('mcpTransform', () =>
    host.mcp.transform((editor) => {
      try {
        for (const [name, config] of editor.list()) {
          const ns = mcpNamespace(name)
          // A server named `opencode` would register its tools under the
          // built-in namespace and shadow `opencode_read`, `opencode_shell` and
          // the rest, so it is dropped whatever the allowlist says.
          if (ns === BUILTIN_NAMESPACE) {
            editor.remove(name)
            removed.add(ns)
            continue
          }
          known.add(ns)
          try {
            configHashes.set(ns, serverConfigHash(ns, config))
          } catch (error) {
            fail('mcp.transform hash ' + ns, error)
            configHashes.delete(ns)
          }
          if (!isServerAllowed(name, allowlist)) {
            editor.remove(name)
            removed.add(ns)
          }
        }
      } catch (error) {
        fail('mcp.transform', error)
      }
    }),
  )

  // 2. Neutralise (or hide) the registered MCP tools.
  await register('toolTransform', () =>
    host.tool.transform((editor) => {
      const run = { descriptions: 0, schemas: 0, flagged: 0, at: now() }
      const hide: string[] = []
      const other = new Set<string>()
      let tools: readonly McpToolLike[] = []
      try {
        tools = editor.list()
      } catch (error) {
        fail('tool.transform list', error)
      }
      toolIndex.clear()
      for (const tool of tools) {
        const ns = tool.options?.namespace
        if (ns === undefined) continue
        if (!known.has(ns)) {
          if (ns !== BUILTIN_NAMESPACE) other.add(ns)
          continue
        }
        toolIndex.set(tool.id, ns)
        try {
          if (!isServerAllowed(ns, allowlist)) {
            editor.remove(tool.id)
            hide.push(tool.id)
            continue
          }
          const description = screenDescription(typeof tool.description === 'string' ? tool.description : '')
          if (description.flagged) run.flagged++
          hidden(ns, description.hiddenCount, 'a tool description')
          const schema = tool.input === undefined ? null : screenSchema(tool.input)
          if (schema) {
            run.flagged += schema.flagged
            hidden(ns, schema.hiddenCount, 'a tool schema')
          }
          if (description.changed || schema) {
            editor.update(tool.id, (draft) => {
              if (description.changed) draft.description = description.text
              if (schema) draft.input = schema.schema
            })
            if (description.changed) run.descriptions++
            if (schema) run.schemas += schema.descriptions
          }
        } catch (error) {
          // Fail closed for this tool: an unscreened description is never shown.
          fail('tool.transform ' + tool.id, error)
          try {
            editor.remove(tool.id)
            hide.push(tool.id)
          } catch (removeError) {
            fail('tool.transform remove ' + tool.id, removeError)
          }
        }
      }
      hiddenTools = hide
      unclassified = [...other].sort()
      lastRun = run
    }),
  )

  // 3. Final refusal for a call into an unlisted server. A throw, never an
  // `effect = "deny"`, because a later plugin can overturn the latter (V6).
  const refuse = (id: string, where: string) => {
    const server = blocked(id)
    if (server === undefined) return
    deniedCalls++
    throw new Error('barmkin-opencode: MCP server "' + server + '" is not on the allowlist (' + where + ')')
  }
  await register('beforeHook', () => host.tool.hook('execute.before', async (event) => refuse(event.tool, 'execute.before')))
  await register('evaluateHook', () => host.permission.hook('evaluate', async (event) => refuse(event.action, 'permission.evaluate')))

  // 4. Model-boundary net: server instructions and the tool descriptions the
  // model is about to read. Never throws.
  await register('contextHook', () =>
    host.session.hook('context', async (context) => {
      try {
        if (known.size === 0) await refreshServers()
        for (const part of context.system ?? []) {
          if (typeof part?.text !== 'string' || !part.text.includes('<mcp_instructions>')) continue
          rewriteText(part, part.text)
        }
        for (const message of context.messages ?? []) {
          const parts = message?.content
          if (!Array.isArray(parts)) continue
          for (const part of parts as ContextTextPart[]) {
            if (part?.type === 'text' && typeof part.text === 'string' && isInstructionsNotice(part.text)) rewriteText(part, part.text)
          }
        }
        for (const [id, tool] of Object.entries(context.tools ?? {})) {
          const server = serverOf(id)
          if (server === undefined || typeof tool?.description !== 'string') continue
          const verdict = screenDescription(tool.description)
          hidden(server, verdict.hiddenCount, 'a tool description')
          if (verdict.changed) tool.description = verdict.text
        }
      } catch (error) {
        fail('session.context', error)
      }
    }),
  )

  function rewriteText(part: ContextTextPart, text: string) {
    const verdict = screenInstructions(text, allowlist)
    for (const [server, count] of Object.entries(verdict.hiddenByServer)) hidden(mcpNamespace(server), count, 'the instructions')
    instructionsFlagged += verdict.flagged
    if (!verdict.changed) return
    instructionsNeutralised += verdict.neutralisedServers.length + verdict.removedServers.length
    part.text = verdict.text
  }

  const status = (): McpGuardStatus => ({
    installed: { ...installed },
    allowlist: [...allowlist],
    allowlistActive: allowlist.length > 0,
    servers: [...known].sort(),
    removedServers: [...removed].sort(),
    hiddenTools: [...hiddenTools],
    unclassifiedNamespaces: [...unclassified],
    neutralised: { descriptions: lastRun.descriptions, schemas: lastRun.schemas, instructions: instructionsNeutralised },
    flagged: lastRun.flagged + instructionsFlagged,
    findings: [...new Set([...findings.values()].filter((f) => hashOf(f.server) === f.hash).map((f) => f.server))].sort(),
    deniedCalls,
    lastRunAt: lastRun.at,
    errors: [...errors],
  })

  // The registry namespaces a request enumerates.
  const enumerated = (context: SessionContextLike): Set<string> => {
    const servers = new Set<string>()
    const named = (text: string) => {
      for (const m of text.matchAll(SERVER_ENTRY)) servers.add(mcpNamespace(m[2]))
    }
    for (const part of context.system ?? []) {
      if (typeof part?.text === 'string' && part.text.includes('<mcp_instructions>')) named(part.text)
    }
    for (const message of context.messages ?? []) {
      const parts = message?.content
      if (!Array.isArray(parts)) continue
      for (const part of parts as ContextTextPart[]) {
        if (part?.type === 'text' && typeof part.text === 'string' && isInstructionsNotice(part.text)) named(part.text)
      }
    }
    for (const id of Object.keys(context.tools ?? {})) {
      const server = serverOf(id)
      if (server !== undefined) servers.add(server)
    }
    return servers
  }

  const findingFor = (server: string): McpFinding | undefined => findings.get(hashOf(server))

  return {
    status,
    healthy: () => Object.values(installed).every(Boolean) && errors.length === 0,
    serverOf,
    findingsFor: (context) => [...enumerated(context)].map(findingFor).filter((f): f is McpFinding => f !== undefined),
    findingFor,
    dispose: async () => {
      for (const registration of registrations.splice(0)) {
        try {
          await registration.dispose()
        } catch (error) {
          fail('dispose', error)
        }
      }
    },
  }
}
