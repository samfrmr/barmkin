// Re-keys OpenCode 2.x tool ids and argument names to the Claude-side keys that
// the shared egress classes (src/lib.ts, egress.ts) classify on (`Bash`/`command`,
// `Edit`/`file_path`, `WebFetch`, `mcp__<server>__<tool>`, ...), so both hosts
// share one policy. 2.x ids and arguments: re-scout S11
// (core/src/tool/plugin/*.ts), observed in the lab as V1-V9, V24, V29, V31, V33:
//
//   shell(command, workdir, timeout, background)      -> Bash
//   read(path, offset, limit)                         -> Read
//   write(path, content)                              -> Write
//   edit(path, oldString, newString, replaceAll)      -> Edit
//   patch(patchText)                                  -> Edit, one call per file in the patch
//   webfetch(url, format, timeout)                    -> WebFetch
//   websearch(...)                                    -> WebSearch
//   subagent(agent, description, prompt, ...)         -> Task
//   skill(id)                                         -> Skill
//   execute(code)                                     -> `execute` (Code Mode, no Claude key)
//   <server>_<tool>                                   -> mcp__<server>__<tool>
//
// The 1.x ids (`bash`, `apply_patch`, `task`) are accepted as aliases. A 2.x
// MCP tool is a flat `<server>_<tool>` id with no marker (V24:
// `evil_fetch_page`), so the adapter should pass its MCP inventory as
// `isMcpTool`; without it any id outside the built-in set is treated as MCP,
// which is the safe direction (it can only add a write-class deny while
// tainted).
//
// Classification only: the barmkin monitor decides on the class ids
// (`decide`), and the adapter turns its deny into a throw (execute.before for
// the early refusal, permission.evaluate for the final recheck, V2, V7).

import { EGRESS_CLASSES, classifyEgress, type EgressCall, type EgressClass } from './lib'

// ---------------------------------------------------------------------------
// Classes: Claude's, plus the one 2.x-only channel.
// ---------------------------------------------------------------------------

// Code Mode's `execute` runs a script whose `fetch` is a raw globalThis.fetch
// with no permission step and no plugin hook (V25, S16). The only visible
// moment is the outer `execute` call, so it is classed as an inline
// interpreter script that makes a network call, which the monitor denies while
// the session is tainted (re-scout section 8, item 4). The monitor's class
// vocabulary is closed, so Code Mode shares that class's id. Inner tool calls
// from Code Mode still fire the ordinary hooks (V24) and are classified as
// themselves.
export const CODEMODE_TOOL = 'execute'

export const CODEMODE_EGRESS_CLASS: EgressClass = {
  id: 'interpreter-net',
  description: 'a Code Mode script (its fetch is an unmediated outbound channel)',
  tools: [CODEMODE_TOOL],
}

export const OPENCODE_EGRESS_CLASSES: readonly EgressClass[] = [...EGRESS_CLASSES, CODEMODE_EGRESS_CLASS]

// ---------------------------------------------------------------------------
// Tool id and argument re-keying.
// ---------------------------------------------------------------------------

const TOOL_KEYS: Readonly<Record<string, string>> = {
  shell: 'Bash',
  bash: 'Bash',
  read: 'Read',
  write: 'Write',
  edit: 'Edit',
  patch: 'Edit',
  apply_patch: 'Edit',
  glob: 'Glob',
  grep: 'Grep',
  webfetch: 'WebFetch',
  websearch: 'WebSearch',
  subagent: 'Task',
  task: 'Task',
  skill: 'Skill',
}

// Ids that are OpenCode's own or this plugin's, never an MCP server's: the
// `opencode_*` management tools (V1 inventory) and barmkin's refusal tool.
const NON_MCP_PREFIXES: readonly string[] = ['opencode_', 'barmkin_']
const NON_MCP_IDS: ReadonlySet<string> = new Set(['question', CODEMODE_TOOL])

export interface NormaliseOptions {
  // Server names, for splitting `<server>_<tool>` into the Claude MCP form.
  mcpServers?: readonly string[]
  // True when the id is a known MCP tool (from the MCP inventory). When
  // omitted, an id outside the built-in set is taken to be MCP.
  isMcpTool?: (id: string) => boolean
}

function asRecord(input: unknown): Record<string, unknown> {
  return input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : {}
}

function isMcp(id: string, opts: NormaliseOptions): boolean {
  if (opts.isMcpTool) return opts.isMcpTool(id)
  if (id in TOOL_KEYS || NON_MCP_IDS.has(id)) return false
  return !NON_MCP_PREFIXES.some((p) => id.startsWith(p))
}

// `evil_fetch_page` -> `mcp__evil__fetch_page`. The longest matching server
// name wins; with none, the whole id is the tool part (the verb scan in
// egress.ts reads the words after the first `__`, so a server name that is a
// write verb cannot cause a false hit when it is split off).
export function mcpKey(id: string, servers: readonly string[] = []): string {
  const match = [...servers].sort((a, b) => b.length - a.length).find((s) => id.startsWith(s + '_') && id.length > s.length + 1)
  return match ? `mcp__${match}__${id.slice(match.length + 1)}` : `mcp__unknown__${id}`
}

// Paths a patch text names. Handles OpenCode's `*** Begin Patch` envelope
// (`*** Add|Update|Delete File:`, `*** Move to:`) and unified-diff `+++`/`---`
// headers. The argument name is S11; the body format is not lab-run, so an
// unparsed patch yields one path-less Edit call and is left to the
// permission-time recheck, which sees the real paths.
export function patchPaths(patchText: string): string[] {
  const paths = new Set<string>()
  for (const m of patchText.matchAll(/^\*\*\* (?:Add|Update|Delete) File:\s*(.+?)\s*$/gm)) paths.add(m[1])
  for (const m of patchText.matchAll(/^\*\*\* Move to:\s*(.+?)\s*$/gm)) paths.add(m[1])
  for (const m of patchText.matchAll(/^(?:\+\+\+|---) (?:[ab]\/)?(\S+)/gm)) if (m[1] !== '/dev/null') paths.add(m[1])
  return [...paths]
}

function withPath(input: Record<string, unknown>, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const out: Record<string, unknown> = { ...input, ...extra }
  if (typeof input.path === 'string' && out.file_path === undefined) out.file_path = input.path
  return out
}

// The Claude-keyed calls for one 2.x tool call. One call for most tools; a
// patch yields one Edit call per file it touches. Never throws on odd input:
// a non-object `input` classifies on the tool id alone.
export function normaliseEgressCalls(tool: string, input: unknown, opts: NormaliseOptions = {}): EgressCall[] {
  const args = asRecord(input)
  if (tool === CODEMODE_TOOL) return [{ tool: CODEMODE_TOOL, input: args }]
  const key = TOOL_KEYS[tool]
  if (key === undefined) {
    return isMcp(tool, opts) ? [{ tool: mcpKey(tool, opts.mcpServers), input: args }] : [{ tool, input: args }]
  }
  switch (tool) {
    case 'patch':
    case 'apply_patch': {
      const text = typeof args.patchText === 'string' ? args.patchText : typeof args.patch === 'string' ? args.patch : ''
      const paths = patchPaths(text)
      return paths.length === 0
        ? [{ tool: 'Edit', input: args }]
        : paths.map((p) => ({ tool: 'Edit', input: { ...args, file_path: p } }))
    }
    case 'edit':
      return [
        {
          tool: 'Edit',
          input: withPath(args, {
            old_string: args.oldString,
            new_string: args.newString,
            replace_all: args.replaceAll,
          }),
        },
      ]
    case 'skill':
      return [{ tool: 'Skill', input: { ...args, skill: args.id ?? args.skill } }]
    case 'write':
    case 'read':
      return [{ tool: key, input: withPath(args) }]
    default:
      return [{ tool: key, input: args }]
  }
}

// The calls a `permission.evaluate` event stands for. At permission time the
// event carries `action` and `resources`, not the tool input (V5-V9, V33):
// `shell` resources are the final parsed commands (one entry per `&&`-separated
// command, V9), `webfetch` the URL, `skill` / `subagent` the id, file tools
// paths. An MCP tool's action is its id with resources `["*"]`, so only the
// tool name classifies (V24); `external_directory` is not an outward effect.
export function normaliseEvaluate(action: string, resources: readonly string[], opts: NormaliseOptions = {}): EgressCall[] {
  const list = resources.filter((r): r is string => typeof r === 'string')
  switch (action) {
    case 'shell':
    case 'bash':
      return list.map((command) => ({ tool: 'Bash', input: { command } }))
    case 'webfetch':
      return list.map((url) => ({ tool: 'WebFetch', input: { url } }))
    case 'websearch':
      return list.map((query) => ({ tool: 'WebSearch', input: { query } }))
    case 'read':
      return list.map((p) => ({ tool: 'Read', input: { path: p, file_path: p } }))
    case 'write':
    case 'edit':
    case 'patch':
    case 'apply_patch':
      return list.map((p) => ({ tool: action === 'write' ? 'Write' : 'Edit', input: { path: p, file_path: p } }))
    case 'skill':
      return list.map((id) => ({ tool: 'Skill', input: { skill: id, id } }))
    case 'subagent':
    case 'task':
      return [{ tool: 'Task', input: {} }]
    case 'external_directory':
      return []
    default:
      return normaliseEgressCalls(action, {}, opts)
  }
}

// ---------------------------------------------------------------------------
// Classification.
// ---------------------------------------------------------------------------

// The classes the calls fall in, each id once, in the order first matched.
// The adapter sends their ids to the monitor's decide.
export function classifyCalls(calls: readonly EgressCall[], classes: readonly EgressClass[] = OPENCODE_EGRESS_CLASSES): EgressClass[] {
  const seen = new Set<string>()
  return calls.flatMap((c) => classifyEgress(c, classes)).filter((c) => !seen.has(c.id) && seen.add(c.id))
}
