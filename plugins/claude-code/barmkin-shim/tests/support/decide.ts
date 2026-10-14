// The verdict the shim shows for a call, as the monitor decides it: the
// monitor's decide (decideLike, the class postures table) composed with the
// shim's describeVerdict. The egress tests ported from barmkin-mod read their
// verdicts through it, as they once read barmkin-mod's local decideEgress.
import { decideLike } from './fake-monitor.ts'
import { describeVerdict, type EgressClass, type EgressVerdict, type ShownLegs } from '../../hooks/lib/egress'
import type { Class } from '../../hooks/lib/proto.ts'

export interface TrifectaLegs {
  untrusted: boolean // A
  sensitive: boolean // B
  untrustedReason: string | null
  sensitiveReason: string | null
}

export function decideEgress(classes: readonly EgressClass[], legs: TrifectaLegs): EgressVerdict {
  const shown: ShownLegs = {
    untrusted: legs.untrusted ? 'fetch' : 'none',
    sensitive: legs.sensitive ? 'credential' : 'none',
    untrustedReason: legs.untrustedReason,
    sensitiveReason: legs.sensitiveReason,
  }
  return describeVerdict(decideLike(classes.map((c) => c.id as Class), shown), classes, shown)
}
