// Pure helpers for the session.start posture self-check: seating in managed
// prependPlugins, plus the sandbox, permission-mode, skill-shell and MCP
// allowlist defaults, and the posture the shim reports to the barmkin monitor
// at register. Takes already-read settings objects and this plugin's own
// manifest name so it can be unit tested without a live $.settings.read()
// call.

import type { Posture } from './proto.ts'

// `prependPlugins`/`appendPlugins` are a managed/policy-only construct (see
// sec-default's own README): a person's settings can't set or override
// them, so seating is checked against the policy-source settings alone.
// The other checks (sandbox, permissions, disableSkillShellExecution) apply
// from whatever source set them, so those are checked against the merged
// settings `$.settings.read()` already returns. A null side means that read
// failed, and the checks it feeds are reported as unverified rather than
// silently passing or dropped.
export interface PostureSettings {
  merged: Record<string, unknown> | null
  policy: Record<string, unknown> | null
}

function pluginIdName(id: string): string {
  return id.split('@')[0] ?? id
}

// The security default's plugin id names it cc-plugin-sec-default; older
// recipes wrote sec-default.
function isSecDefault(id: string): boolean {
  const name = pluginIdName(id)
  return name === 'cc-plugin-sec-default' || name === 'sec-default'
}

function record(v: unknown): Record<string, unknown> | null {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

// Whether the sandbox lets a sandboxed command open every Unix socket, which
// would let it reach the monitor's socket. Read from sandbox.network, and from
// sandbox itself in case a recipe put it there.
function allowsAllUnixSockets(merged: Record<string, unknown>): boolean {
  const sandbox = record(merged.sandbox)
  return sandbox?.allowAllUnixSockets === true || record(sandbox?.network)?.allowAllUnixSockets === true
}

// The posture the shim reports at register: the monitor refuses a host whose
// tools do not run in a sandbox, or whose sandbox opens every Unix socket. A
// failed settings read reports the sandbox as off, so register is refused
// rather than vouched for.
export function reportedPosture(merged: Record<string, unknown> | null): Posture {
  if (merged === null) return { sandbox_enabled: false, allow_all_unix_sockets: false }
  return { sandbox_enabled: record(merged.sandbox)?.enabled === true, allow_all_unix_sockets: allowsAllUnixSockets(merged) }
}

export function checkPosture(settings: PostureSettings, pluginName: string, mcpAllowlist: readonly string[]): string[] {
  const warnings: string[] = []

  const rawPrepend = settings.policy?.prependPlugins
  const prependPlugins = Array.isArray(rawPrepend) ? rawPrepend.filter((v): v is string => typeof v === 'string') : null

  const ourIndex = prependPlugins ? prependPlugins.findIndex((id) => pluginIdName(id) === pluginName) : -1
  const secDefaultIndex = prependPlugins ? prependPlugins.findIndex(isSecDefault) : -1

  if (settings.policy === null) {
    warnings.push('seating unverified: policy settings read failed.')
  } else if (prependPlugins === null || ourIndex === -1) {
    warnings.push(
      pluginName + ' is not in managed prependPlugins, so it cannot see skill text or CLAUDE.md: seat it (the managed-settings recipe in the barmkin README).',
    )
  } else if (secDefaultIndex === -1) {
    warnings.push(
      'managed prependPlugins does not list cc-plugin-sec-default@builtin, which unseats the security default: list it after ' + pluginName + '.',
    )
  } else if (secDefaultIndex < ourIndex) {
    warnings.push(
      'sec-default is seated ahead of ' + pluginName + ', hiding skill.prompt, prompt.context and prompt.section: seat ' + pluginName + ' first.',
    )
  }

  if (settings.merged === null) {
    warnings.push('sandbox, Unix sockets, defaultMode and disableSkillShellExecution unverified: settings read failed.')
  } else {
    const merged = settings.merged
    const permissions = merged.permissions
    const defaultMode =
      permissions && typeof permissions === 'object' && !Array.isArray(permissions)
        ? (permissions as Record<string, unknown>).defaultMode
        : undefined
    if (defaultMode === 'bypassPermissions') {
      warnings.push('permissions.defaultMode is bypassPermissions, skipping every tool.check prompt: use default.')
    }

    const sandbox = merged.sandbox
    const sandboxEnabled =
      sandbox && typeof sandbox === 'object' && !Array.isArray(sandbox) ? (sandbox as Record<string, unknown>).enabled : undefined
    if (sandboxEnabled !== true) {
      warnings.push('Bash sandbox is off, so no OS egress floor backs taint-gated denies: set sandbox.enabled to true.')
    }
    if (allowsAllUnixSockets(merged)) {
      warnings.push('sandbox.network.allowAllUnixSockets is set, so a sandboxed command can reach the barmkin monitor socket: remove it.')
    }

    if (merged.disableSkillShellExecution !== true) {
      warnings.push('disableSkillShellExecution is unset, so skill inline shell bypasses tool.call guards: set it to true.')
    }
  }

  if (mcpAllowlist.length === 0) {
    warnings.push('mcp_server_allowlist is empty, so any MCP server may run tools (audit-only): list trusted servers.')
  }

  return warnings
}
