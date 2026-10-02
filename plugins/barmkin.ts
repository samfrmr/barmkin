// Barmkin plugin for opencode.
//
// Spawns `barmkin eval` as a subprocess on every tool.execute.before event.
// The binary reads an AdapterRequest from stdin and exits:
//   exit 0 = allow (silent)
//   exit 2 = deny (stderr contains the reason)
//
// The plugin parses the exit code. On deny it throws an Error with the
// reason, which opencode shows to the LLM as a tool failure. On allow
// it returns silently.
//
// Dynamic layer (opencode 1.x, deny-only - report.md §5c): the binary's
// optional second evaluation stage can additionally produce "escalate".
// opencode 1.x's tool.execute.before can only pass or throw - it has no
// way to prompt a human - so the binary always renders escalate as a
// deny (exit 2) for this plugin, never exit 0. This plugin declares
// "capabilities":["escalate"] on every request so the binary knows this
// caller understands that outcome exists (capability negotiation is
// mandatory for opencode per the design report: without it, an old
// plugin that ignored stdout could misread a future ask-style escalate
// rendering as exit-0 allow). opencode 2.x gets a real ask via
// ctx.permission.hook("evaluate") and needs its own plugin variant -
// out of scope here.
//
// All telemetry (OTel, audit log, stats) is handled by the Go binary.
// The plugin is intentionally thin - just normalize + spawn + check exit code.
//
// Environment variables:
//   BARMKIN_BIN       binary path            (default "barmkin")
//   BARMKIN_TITLE     toast title            (default "Barmkin")
//   BARMKIN_TOAST     set "1" to enable toast notifications
//   BARMKIN_DRY_RUN   set "1" to log denials without blocking
//   BARMKIN_OFF       set "1" to disable plugin entirely

import type { Plugin } from "@opencode-ai/plugin"

// ── Configuration ────────────────────────────────────────────────────────

const BIN = process.env.BARMKIN_BIN || "barmkin"
const DRY_RUN = process.env.BARMKIN_DRY_RUN === "1"
const DISABLED = process.env.BARMKIN_OFF === "1"
const TOAST = process.env.BARMKIN_TOAST === "1"
const TITLE = `● ${process.env.BARMKIN_TITLE || "Barmkin"}`
const AGENT_ID = `opencode-${process.env.USER || "unknown"}`

// ── Toast ────────────────────────────────────────────────────────────────
// Optional - disabled by default. Uses the opencode SDK client's
// tui.showToast() method. Only fires when BARMKIN_TOAST=1.

let client: any = null

async function toast(variant: "info" | "warning" | "error", message: string, duration = 8000) {
  if (!TOAST || !client?.tui) return
  try {
    await client.tui.showToast({ body: { title: TITLE, message, variant, duration } })
  } catch {}
}

// ── Normalization ────────────────────────────────────────────────────────
// Maps opencode tool names and args to the AdapterRequest format
// that barmkin expects. Mirrors sondera's normalize.ts logic.

const TOOL_ACTION: Record<string, string> = {
  bash: "ShellCommand", read: "FileRead", edit: "FileEdit",
  write: "FileWrite", apply_patch: "FileEdit", glob: "FileSearch",
  grep: "ContentSearch", webfetch: "WebFetch", websearch: "WebSearch",
}

// Extract a string from an unknown value, returning undefined if empty.
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined
}

// Convert raw opencode tool args into the normalized args dict
// that AdapterRequest expects (command for bash, path for files, etc).
function toolArgs(tool: string, a: Record<string, unknown>): Record<string, unknown> {
  switch (tool) {
    case "bash": return { command: a.command || "", workdir: str(a.workdir) }
    case "read": return { path: str(a.filePath) || str(a.path) || "" }
    case "edit": return { path: str(a.filePath) || str(a.path) || "" }
    case "write": return { path: str(a.filePath) || str(a.path) || "" }
    default: return a
  }
}

// ── Dynamic-layer status ────────────────────────────────────────────────
// Queried once at plugin startup (not per-call, to avoid adding
// latency) so a per-call timeout below knows whether to fail open
// (today's behavior, safe when there's no semantic layer to bypass) or
// fail closed (the dynamic layer is enabled, so a hung binary must
// never silently allow the call - report.md §5c: "the plugin should
// fail closed on timeout when the binary reports that the dynamic
// layer is enabled"). Left false - fail open - on any spawn error,
// non-zero exit, or timeout of the status check itself, since only an
// explicit "enabled" report from the binary should tighten this.

let dynamicLayerEnabled = false

async function checkDynamicStatus(): Promise<void> {
  try {
    const proc = Bun.spawn({ cmd: [BIN, "dynamic-status"], stdout: "pipe", stderr: "pipe" })
    const code = await Promise.race<number | null>([
      proc.exited,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), EVAL_TIMEOUT_MS)),
    ])
    if (code !== 0) {
      try { proc.kill() } catch {}
      return
    }
    const out = await Bun.readableStreamToText(proc.stdout)
    dynamicLayerEnabled = out.trim() === "enabled"
  } catch {
    // Spawn failure - leave dynamicLayerEnabled false, consistent with
    // evaluate()'s own fail-open on a broken binary.
  }
}

// ── Evaluate ─────────────────────────────────────────────────────────────
// Spawn `barmkin eval`, pipe the AdapterRequest JSON to stdin,
// and check the exit code.

const EVAL_TIMEOUT_MS = 3000

async function evaluate(
  tool: string,
  args: Record<string, unknown>,
  cwd: string,
  sid: string,
): Promise<string | null> {
  const req = JSON.stringify({
    trajectory_id: sid || "unknown",
    agent_id: AGENT_ID,
    tool,
    action: TOOL_ACTION[tool] || "ToolCall",
    args: toolArgs(tool, args),
    cwd,
    event_type: "before",
    capabilities: ["escalate"],
  })

  try {
    const proc = Bun.spawn({
      cmd: [BIN, "eval"],
      stdin: "pipe",
      stdout: "pipe",
      stderr: "pipe",
    })
    proc.stdin.write(req)
    proc.stdin.end()

    // Race the exit against a timeout. On timeout, kill the process and
    // fail open so a hung binary never blocks a tool call indefinitely.
    const code = await Promise.race<number | null>([
      proc.exited,
      new Promise<null>((resolve) => setTimeout(() => resolve(null), EVAL_TIMEOUT_MS)),
    ])

    if (code === null) {
      try { proc.kill() } catch {}
      if (dynamicLayerEnabled) {
        return "barmkin timed out with the dynamic layer enabled; failing closed"
      }
      return null // timeout, no dynamic layer to bypass - fail open
    }

    // Exit 2 = deny. Read stderr for the reason.
    if (code === 2) {
      const stderr = await Bun.readableStreamToText(proc.stderr)
      return stderr.trim() || "denied"
    }
    // Exit 0 = allow. Silent.
    return null
  } catch {
    // Spawn failure - fail open so a broken guardrail doesn't block work.
    return null
  }
}

// ── Plugin ───────────────────────────────────────────────────────────────

export const BarmkinPlugin: Plugin = async (ctx: any) => {
  if (DISABLED) return {}

  // Store the SDK client for toast notifications.
  client = ctx.client

  // Learn the binary's dynamic-layer posture once, up front, so a
  // later per-call timeout knows whether to fail open or closed.
  await checkDynamicStatus()

  // Fire startup toast if toasts are enabled.
  toast("info", DRY_RUN ? "dry-run mode" : "enforcing")

  return {
    // Intercept every tool call before execution.
    "tool.execute.before": async (input: any, output: any) => {
      if (!output?.args || typeof output.args !== "object") return

      const reason = await evaluate(
        input.tool,
        output.args as Record<string, unknown>,
        ctx.directory,
        input.sessionID ?? "",
      )

      // null = allowed or daemon unavailable - fail open.
      if (!reason) return

      // Dry-run mode: warn but don't block.
      if (DRY_RUN) {
        await toast("warning", `[dry-run] would deny: ${reason}`)
        return
      }

      // Deny: toast (if enabled) + throw error for the LLM to see.
      await toast("error", reason)
      throw new Error(reason)
    },
  }
}
