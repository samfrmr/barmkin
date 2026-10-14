// The host-neutral library this shim shares with the Claude Code shim
// (plugins/claude-code/barmkin-shim/hooks/lib): secret redaction, the
// invisible-text scrub, the egress classes, the screen's local inputs and the
// MCP and skill guards, and the root policy. One copy serves both hosts, so a fix to the policy
// lands in both; this file is the one place that names its path. The bundle
// (see RELEASE-CHECKLIST.md "Build the bundle") inlines it.

export { REDACTION_RULES } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/redaction-rules'
export {
  POLICY_PATH,
  MAX_POLICY_BYTES,
  BUILTIN_POLICY,
  policyFromRead,
  describePolicy,
  type ActivePolicy,
  type PolicyLoad,
  type PolicyRead,
} from '../../../plugins/claude-code/barmkin-shim/hooks/lib/policy'
export {
  redactInEitherView,
  classifierInput,
  WITHHELD_TEXT,
  containsSecretInEitherView,
  measureResult,
  exceedsScreenedLimit,
  SCREENED_LIMIT_REASON,
  PAGING_ADVICE,
} from '../../../plugins/claude-code/barmkin-shim/hooks/lib/redaction'
export { scrubInvisible } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/scrub'
export { isOutsideCwd, heuristicInjectionScore, UNTRUSTED_CONTENT_WARNING } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/taint'
export {
  EGRESS_CLASSES,
  classifyEgress,
  describeVerdict,
  touchesSecretPath,
  SOURCE_TEXT,
  type EgressCall,
  type EgressClass,
  type EgressVerdict,
  type ShownLegs,
} from '../../../plugins/claude-code/barmkin-shim/hooks/lib/egress'
export { planWindows } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/classifier-windows'
export { skillBodyWithheldText, neutralizeSkillListing } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/skill-guard'
export { isAllowedServer, neutralizeDescription } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/mcp-guard'
export { extractResultText } from '../../../plugins/claude-code/barmkin-shim/hooks/lib/tool-result'
