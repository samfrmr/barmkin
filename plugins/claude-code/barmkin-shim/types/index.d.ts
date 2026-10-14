// $.state shape for barmkin-shim. Declared here so `claude plugin validate`
// can check hooks/register.ts against it (see plugin.json's "types" field).
// The barmkin monitor holds the session's legs; these are the shim's cache of
// what it last reported, for the HUD and the status command.
declare module 'claude-code' {
  interface PluginState {
    'barmkin-shim': {
      // The legs the monitor last reported: the source that first raised
      // each, or 'none'. Legs never fall: the taint is sticky.
      untrustedLeg: string
      sensitiveLeg: string
      // Why each leg rose, as the shim saw it (the monitor keeps no text).
      untrustedReason: string | null
      sensitiveReason: string | null

      // 'ok' when the last monitor request was answered, else why it failed.
      monitorState: string
      // The monitor's classifier state from its last status answer.
      classifierState: string

      // The first session id this process registered: its lineage root.
      rootSession: string | null

      // The last egress call the monitor denied or warned on.
      lastEgress: {
        tool: string
        classIds: string[]
        decision: 'deny' | 'warn'
        rule: string
        at: number
      } | null

      // The monitor's last screen decision, for the explanation surface.
      lastScreen: {
        toolUseId: string
        label: string
        decision: 'pass' | 'escalate' | 'deny'
        scores: { injection: number; credentials: number; exfiltration: number }
        gap: 'none' | 'scan_limit' | 'unclassified'
        at: number
      } | null
    }
  }
}
