// TUI half of barmkin-opencode (W4). OpenCode resolves this file by name
// (`tui.tsx` beside the server entry), compiles it at runtime and runs it in
// the terminal UI; it is not exported from server.ts and shares no state with
// it except through the status RPC (src/status-rpc.ts).
//
// What it shows, per re-scout section 2.1 (V34-V36): a footer chip
// (`prompt.footer.status`), a sidebar block (`sidebar.content`) and a banner in
// `session.composer.top`, which renders directly above "Permission required"
// and is the only place a guard note can sit next to a permission prompt. A
// toast announces a seat change. `/barmkin-status` prints everything.
//
// Limits it cannot get around: if the server half failed to set up, this half
// never loads (V35), so a guard that cannot start reports nothing here.

import type { Plugin } from '@opencode/plugin/tui'
import { createSignal, For, Show } from 'solid-js'
import { GUARD_PLUGIN_ID, isStatusReport, statusRpc, type StatusReport } from './src/status-rpc'
import { buildView, guardInventory, statusText, toastFor, type Level, type View } from './src/tui-view'

const POLL_MS = 10_000

type Context = Plugin.Context

function colorOf(context: Context, level: Level) {
  const { feedback } = context.theme.text
  return level === 'unguarded' ? feedback.error.base : level === 'degraded' ? feedback.warning.base : feedback.success.base
}

function errorText(error: unknown): string {
  if (error && typeof error === 'object') {
    const { type, message } = error as { type?: unknown; message?: unknown }
    if (typeof message === 'string') return (typeof type === 'string' ? type + ': ' : '') + message
  }
  return String(error)
}

export default {
  id: GUARD_PLUGIN_ID + '.tui',
  setup(context: Context) {
    const initial: View = buildView({ inventory: { presence: 'active' }, reportError: 'no answer yet' })
    const [view, setView] = createSignal<View>(initial)
    let previous: View | undefined
    let disposed = false
    let inflight = false

    const refresh = async () => {
      if (disposed || inflight) return
      inflight = true
      try {
        const location = context.location ?? context.data.location.default()
        const inventory = await context.client.plugin
          .list({ location })
          .then((result) => guardInventory(result.data))
          .catch(() => guardInventory(undefined))
        let report: StatusReport | undefined
        let reportError: string | undefined
        if (inventory.presence === 'active') {
          try {
            const answer: unknown = await context.client.rpc(statusRpc).status({})
            if (isStatusReport(answer)) report = answer
            else reportError = 'unexpected status payload'
          } catch (error) {
            reportError = errorText(error)
          }
        }
        if (disposed) return
        const next = buildView({ inventory, report, reportError })
        const toast = toastFor(previous, next)
        previous = next
        setView(next)
        if (toast) context.ui.toast.show({ ...toast, duration: toast.variant === 'info' ? 5000 : 12000 })
      } finally {
        inflight = false
      }
    }

    context.ui.slot({
      append: 'prompt.footer.status',
      render: () => (
        <box flexShrink={0}>
          <text fg={colorOf(context, view().level)} wrapMode="none">
            {view().chip}
          </text>
        </box>
      ),
    })

    context.ui.slot({
      append: 'sidebar.content',
      render: () => (
        <box>
          <text fg={colorOf(context, view().level)}>
            <b>{view().headline}</b>
          </text>
          <For each={view().lines}>
            {(line) => (
              <text fg={context.theme.text.muted} wrapMode="word">
                {line}
              </text>
            )}
          </For>
        </box>
      ),
    })

    context.ui.slot({
      prepend: 'session.composer.top',
      render: () => (
        <Show when={view().banner}>
          <box flexShrink={0}>
            <text fg={colorOf(context, view().level === 'ok' ? 'degraded' : view().level)} wrapMode="word">
              {view().banner}
            </text>
          </box>
        </Show>
      ),
    })

    context.keymap.layer(() => ({
      mode: 'global',
      commands: [
        {
          id: 'barmkin.status',
          title: 'barmkin-opencode status',
          description: 'Posture line, seat, taint, monitor and MCP guard state',
          group: 'barmkin',
          palette: true,
          slash: { name: 'barmkin-status' },
          async run() {
            await refresh()
            await context.ui.dialog.alert({ title: 'barmkin-opencode status', message: statusText(view()) })
          },
        },
      ],
    }))

    const offs: Array<() => void> = []
    offs.push(context.data.on('plugin.updated', () => void refresh()))
    const events = new AbortController()
    try {
      offs.push(context.client.rpc(statusRpc).events.on('changed', () => void refresh(), { signal: events.signal }))
    } catch {
      // No event channel: the poll below still catches a change.
    }
    const timer = setInterval(() => void refresh(), POLL_MS)
    void refresh()

    return () => {
      disposed = true
      clearInterval(timer)
      events.abort()
      for (const off of offs) off()
    }
  },
} satisfies Plugin.Definition
