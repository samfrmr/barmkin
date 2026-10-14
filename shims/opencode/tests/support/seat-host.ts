// A model of the OpenCode 2.x plugin host, limited to what the T-SEAT suite depends on.
//
// Every rule below is a behaviour the 2.x re-scout verified against the real 2.0.27 binary
// (check ids V1-V16, V38 in data/opencode-port-2x-rescout/report.md). This is a model, not
// the binary: it pins the contract the seat recipe relies on, and the per-release re-run in
// RELEASE-CHECKLIST.md is what confirms a new OpenCode release still behaves this way.
//
// Modelled rules:
//   - One flat plugin chain assembled from seven seats in a fixed order (V1).
//   - `-id`, `-x.*` and `-*` entries remove plugins already in the chain; a later seat is
//     therefore out of reach of an earlier seat's removal (V10-V13).
//   - OPENCODE_DISABLE_PROJECT_CONFIG=1 drops every project seat (V14).
//   - Policies from the user-global config deny or allow `plugin:<id>`; a project's policies
//     never outrank them (V15). A removal entry still unloads an allowlisted plugin (V16).
//   - A throw in execute.before or permission.evaluate refuses the tool and is final; setting
//     `effect = "deny"` is overridable by a later plugin (V2, V5-V7).
//   - `event.tool` is writable in execute.before (tool rename, V8); shell.create.before can
//     rewrite the command after every tool hook (V9) and carries no session identity.
//   - A plugin whose setup throws is dropped silently (V17); one whose transform throws has
//     every hook removed mid-session (V19).
//
// Besides the hooks, a plugin's context answers what the guard asks the host: its options,
// the project directory, a session's parent and history (`session.get`, `session.context`),
// and empty tool, MCP and plugin inventories. Every other member is an async no-op.

export type Hook = (event: any) => unknown | Promise<unknown>

export interface PluginDef {
  id: string
  setup(ctx: any): unknown | Promise<unknown>
}

// Chain order, first to last (V1). OPENCODE_CONFIG_CONTENT is the last third-party seat.
export const SEATS = [
  'global-plugins-dir',
  'project-plugins-dir',
  'global-config',
  'config-file',
  'project-config',
  'project-dot-opencode-config',
  'inline-config',
] as const
export type Seat = (typeof SEATS)[number]

const PROJECT_SEATS: readonly Seat[] = ['project-plugins-dir', 'project-config', 'project-dot-opencode-config']

export interface Policy {
  action: 'integration.use'
  resource: string
  effect: 'allow' | 'deny'
}

export interface SeatConfig {
  // Registry keys to load, or removal entries: "-id", "-prefix.*", "-*".
  plugins?: string[]
  policies?: Policy[]
}

export interface HostInput {
  seats: Partial<Record<Seat, SeatConfig>>
  registry: Record<string, PluginDef>
  env?: { OPENCODE_DISABLE_PROJECT_CONFIG?: string }
  // Each plugin's options, by plugin id.
  options?: Record<string, Record<string, unknown>>
  // The sessions the host knows: a subagent's parent, and the message types in a
  // session's history. A session not listed is top-level with an empty history.
  sessions?: SessionTable
}

export interface SessionTable {
  parents?: Record<string, string>
  history?: Record<string, string[]>
}

export const PROJECT_DIR = '/work/project'

export interface ToolCall {
  // The call id; one is made up when omitted.
  id?: string
  sessionID: string
  tool: string
  input: Record<string, unknown>
  // The text the tool would hand back; webfetch uses it to deliver an injection payload.
  result?: string
}

export interface ToolOutcome {
  outcome: 'executed' | 'refused'
  stage?: 'execute.before' | 'shell.create.before' | 'permission.evaluate'
  message?: string
  // What the tool actually ran with, after every rewrite.
  ran?: { tool: string; resource: string }
  // What the model read back: the result's text after every after-hook.
  delivered?: string
}

interface Registered {
  pluginId: string
  name: string
  fn: Hook
}

export class SeatHost {
  readonly chain: string[] = []
  readonly failedSetup: string[] = []
  readonly disabledMidSession: string[] = []
  readonly executed: { tool: string; resource: string }[] = []
  readonly builtinsRemoved: boolean
  // The host's sessions; a test may change them as a conversation goes on.
  readonly sessions: Required<SessionTable>
  private hooks: Registered[] = []
  private transforms: Registered[] = []
  // The last model request, as the hooks left it.
  lastRequest: { system: { type: string; text: string }[]; tools: Record<string, { description: string }> } | null = null
  private options: Record<string, Record<string, unknown>>
  private calls = 0

  private constructor(builtinsRemoved: boolean, input: HostInput) {
    this.builtinsRemoved = builtinsRemoved
    this.options = input.options ?? {}
    this.sessions = { parents: { ...input.sessions?.parents }, history: { ...input.sessions?.history } }
  }

  static async create(input: HostInput): Promise<SeatHost> {
    const projectOff = input.env?.OPENCODE_DISABLE_PROJECT_CONFIG === '1'
    const active = SEATS.filter((seat) => !(projectOff && PROJECT_SEATS.includes(seat)))

    let loaded: { key: string; def: PluginDef }[] = []
    let builtinsRemoved = false
    for (const seat of active) {
      for (const entry of input.seats[seat]?.plugins ?? []) {
        if (entry === '-*') {
          loaded = []
          builtinsRemoved = true
        } else if (entry.startsWith('-') && entry.endsWith('.*')) {
          const prefix = entry.slice(1, -1)
          loaded = loaded.filter((p) => !p.def.id.startsWith(prefix))
        } else if (entry.startsWith('-')) {
          loaded = loaded.filter((p) => p.def.id !== entry.slice(1))
        } else {
          const def = input.registry[entry]
          if (def) loaded.push({ key: entry, def })
        }
      }
    }

    // Only non-project policies count: a repository cannot out-vote the user's allowlist (V15).
    const policies = active
      .filter((seat) => !PROJECT_SEATS.includes(seat))
      .flatMap((seat) => input.seats[seat]?.policies ?? [])
    loaded = loaded.filter((p) => pluginAllowed(policies, p.def.id))

    const host = new SeatHost(builtinsRemoved, input)
    for (const { def } of loaded) {
      try {
        await def.setup(host.contextFor(def.id))
        host.chain.push(def.id)
      } catch {
        host.hooks = host.hooks.filter((h) => h.pluginId !== def.id)
        host.transforms = host.transforms.filter((h) => h.pluginId !== def.id)
        host.failedSetup.push(def.id)
      }
    }
    return host
  }

  // A recording ctx: `ctx.<domain>.hook(name, fn)` and `ctx.<domain>.transform(fn)` register;
  // every other member resolves to an async no-op so a plugin can call it freely.
  private contextFor(pluginId: string): any {
    const noop = new Proxy(() => undefined, {
      get: () => noop,
      apply: async () => undefined,
    })
    const domain = (domainName: string) =>
      new Proxy(
        {
          hook: (name: string, fn: Hook) => {
            this.hooks.push({ pluginId, name: `${domainName}.${name}`, fn })
          },
          transform: (fn: Hook) => {
            this.transforms.push({ pluginId, name: `${domainName}.transform`, fn })
          },
        } as Record<string, unknown>,
        { get: (target, prop: string) => (prop in target ? target[prop] : noop) },
      )
    const domains = new Map<string, unknown>()
    const fixed: Record<string, unknown> = {
      options: this.options[pluginId] ?? {},
      location: { directory: PROJECT_DIR },
    }
    const answers: Record<string, Record<string, unknown>> = {
      session: {
        get: async ({ sessionID }: { sessionID: string }) => {
          const parentID = this.sessions.parents[sessionID]
          return { id: sessionID, ...(parentID ? { parentID } : {}) }
        },
        context: async ({ sessionID }: { sessionID: string }) => (this.sessions.history[sessionID] ?? []).map((type, i) => ({ id: `msg_${i}`, type })),
      },
      tool: { list: async () => [] },
      mcp: { list: async () => [] },
      plugin: { list: async () => [] },
    }
    return new Proxy(
      {},
      {
        get: (_, prop: string) => {
          if (prop in fixed) return fixed[prop]
          if (!domains.has(prop)) {
            const d = domain(prop) as Record<string, unknown>
            domains.set(prop, new Proxy(d, { get: (target, member: string) => answers[prop]?.[member] ?? target[member] }))
          }
          return domains.get(prop)
        },
      },
    )
  }

  // Runs the transforms registered under one name (`mcp.transform`, `tool.transform`) with
  // the supplied editor, disabling a plugin that throws (V19).
  async runTransform(name: string, editor: unknown): Promise<void> {
    for (const t of this.transforms.filter((x) => x.name === name)) {
      if (this.disabledMidSession.includes(t.pluginId)) continue
      try {
        await t.fn(editor)
      } catch {
        this.disabledMidSession.push(t.pluginId)
        this.hooks = this.hooks.filter((h) => h.pluginId !== t.pluginId)
        this.transforms = this.transforms.filter((x) => x.pluginId !== t.pluginId)
      }
    }
  }

  // Runs every hook registered under one name, in chain order, with the event.
  async runHooks(name: string, event: unknown): Promise<void> {
    for (const h of this.hooksNamed(name)) await h.fn(event)
  }

  // A primary model request for a session, through every session.context hook. Returns the
  // thrown message when a hook refused to send it.
  async request(sessionID: string, tools: Record<string, { description: string; input?: unknown }> = {}, system: { type: 'text'; text: string }[] = []): Promise<string | null> {
    const event = { sessionID, agent: 'build', model: { providerID: 'lab', modelID: 'm' }, system, messages: [], options: {}, tools }
    this.lastRequest = event
    try {
      await this.runHooks('session.context', event)
      return null
    } catch (err) {
      return messageOf(err)
    }
  }

  // Starts a call's execute.before hooks and leaves it in flight; `finish` runs its
  // execute.after hooks and returns what the model read back.
  async startTool(call: ToolCall): Promise<{ outcome: 'started' | 'refused'; message?: string; finish: () => Promise<string> }> {
    const id = call.id ?? `call_${++this.calls}`
    const event = { id, sessionID: call.sessionID, tool: call.tool, input: { ...call.input }, agent: 'build', messageID: 'msg' }
    const finish = async () => {
      const after = { ...event, status: 'completed' as const, result: { output: call.result ?? '', content: [{ type: 'text', text: call.result ?? '' }] } }
      try {
        for (const h of this.hooksNamed('tool.execute.after')) await h.fn(after)
      } catch (err) {
        return messageOf(err)
      }
      return deliveredText(after.result) + '\n' + JSON.stringify(after.result)
    }
    try {
      await this.runHooks('tool.execute.before', event)
      return { outcome: 'started', finish }
    } catch (err) {
      return { outcome: 'refused', message: messageOf(err), finish }
    }
  }

  hooksNamed(name: string): Registered[] {
    return this.hooks.filter((h) => h.name === name)
  }

  transformsRegistered(): Registered[] {
    return [...this.transforms]
  }

  // Runs every registered transform with the supplied editor, disabling a plugin that throws (V19).
  async runTransforms(editor: unknown): Promise<void> {
    for (const t of this.transforms) {
      if (this.disabledMidSession.includes(t.pluginId)) continue
      try {
        await t.fn(editor)
      } catch {
        this.disabledMidSession.push(t.pluginId)
        this.hooks = this.hooks.filter((h) => h.pluginId !== t.pluginId)
        this.transforms = this.transforms.filter((x) => x.pluginId !== t.pluginId)
      }
    }
  }

  async callTool(call: ToolCall): Promise<ToolOutcome> {
    const id = call.id ?? `call_${++this.calls}`
    const event: { id: string; agent: string; messageID: string; sessionID: string; tool: string; input: Record<string, unknown> } = {
      id,
      agent: 'build',
      messageID: 'msg',
      sessionID: call.sessionID,
      tool: call.tool,
      input: { ...call.input },
    }
    try {
      for (const h of this.hooksNamed('tool.execute.before')) await h.fn(event)
    } catch (err) {
      return { outcome: 'refused', stage: 'execute.before', message: messageOf(err) }
    }

    // The tool that runs is the one named after every before-hook (V8).
    const tool = event.tool
    let resource = resourceOf(tool, event.input)

    if (tool === 'shell') {
      // No sessionID here: 2.x does not give shell.create.before the session of the call.
      const shellEvent = { command: String(event.input.command ?? ''), workdir: event.input.workdir }
      try {
        for (const h of this.hooksNamed('shell.create.before')) await h.fn(shellEvent)
      } catch (err) {
        return { outcome: 'refused', stage: 'shell.create.before', message: messageOf(err) }
      }
      resource = shellEvent.command
    }

    const evaluation = { sessionID: call.sessionID, action: tool, tool, resources: [resource], effect: 'allow' as string, message: undefined as string | undefined }
    try {
      for (const h of this.hooksNamed('permission.evaluate')) await h.fn(evaluation)
    } catch (err) {
      return { outcome: 'refused', stage: 'permission.evaluate', message: messageOf(err) }
    }
    if (evaluation.effect === 'deny') {
      return { outcome: 'refused', stage: 'permission.evaluate', message: evaluation.message ?? 'permission.rejected' }
    }

    const ran = { tool, resource }
    this.executed.push(ran)
    const text = call.result ?? ''
    const after = {
      id,
      agent: 'build',
      messageID: 'msg',
      sessionID: call.sessionID,
      tool,
      input: event.input,
      status: 'completed' as const,
      result: { output: text, content: [{ type: 'text', text }] },
    }
    try {
      for (const h of this.hooksNamed('tool.execute.after')) await h.fn(after)
    } catch (err) {
      // A throw after execution reports an error but the command has already run (V22).
      return { outcome: 'executed', ran, delivered: messageOf(err) }
    }
    return { outcome: 'executed', ran, delivered: deliveredText(after.result) }
  }
}

function pluginAllowed(policies: Policy[], id: string): boolean {
  const matching = policies.filter(
    (p) => p.action === 'integration.use' && (p.resource === `plugin:${id}` || p.resource === 'plugin:*'),
  )
  const specific = matching.find((p) => p.resource === `plugin:${id}`)
  if (specific) return specific.effect === 'allow'
  const wildcard = matching.find((p) => p.resource === 'plugin:*')
  return wildcard ? wildcard.effect === 'allow' : true
}

function resourceOf(tool: string, input: Record<string, unknown>): string {
  if (tool === 'shell') return String(input.command ?? '')
  if (tool === 'webfetch') return String(input.url ?? '')
  return String(input.path ?? input.patchText ?? '*')
}

function deliveredText(result: unknown): string {
  const content = (result as { content?: unknown } | null)?.content
  if (!Array.isArray(content)) return ''
  return content.map((p) => (p && typeof p === 'object' && typeof (p as { text?: unknown }).text === 'string' ? (p as { text: string }).text : '')).join('\n')
}

function messageOf(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

// A recording stand-in for a hostile or merely later plugin, used to drive the finality tests.
export function probePlugin(
  id: string,
  hooks: {
    before?: Hook
    shellBefore?: Hook
    evaluate?: Hook
    after?: Hook
    transform?: Hook
    failSetup?: boolean
  },
): PluginDef {
  return {
    id,
    setup(ctx) {
      if (hooks.failSetup) throw new Error(`${id}: setup failed`)
      if (hooks.before) ctx.tool.hook('execute.before', hooks.before)
      if (hooks.shellBefore) ctx.shell.hook('create.before', hooks.shellBefore)
      if (hooks.evaluate) ctx.permission.hook('evaluate', hooks.evaluate)
      if (hooks.after) ctx.tool.hook('execute.after', hooks.after)
      if (hooks.transform) ctx.tool.transform(hooks.transform)
    },
  }
}
