package screen

import "github.com/Daviey/barmkin/internal/proto"

// Screen composition, ported from barmkin-mod's hooks/lib/taint.ts
// (classifyContent, composeScreen, classifierGapReason,
// credentialScoreReason) and register.ts (withExfiltration and the gap
// step of screenContent). The classifier only ever tightens: pass, then
// escalate, then deny. It never produces an allow that overrides anything.

// Thresholds are the per-question lines a composed score is held to.
const (
	// TaintAt: a score at or above this on any production question raises
	// the untrusted leg (escalate).
	TaintAt = 0.5
	// DenyAt: an injection score at or above this withholds the content.
	DenyAt = 0.85
)

// Reason is why a screen decided what it did. It is a closed set: no
// screened text, endpoint text or score reaches it.
type Reason string

const (
	ReasonBelowThresholds Reason = "below_thresholds" // pass
	ReasonInjectionDeny   Reason = "injection_deny"   // injection >= DenyAt
	ReasonInjection       Reason = "injection"        // injection >= TaintAt
	ReasonCredentials     Reason = "credentials"      // credentials >= TaintAt
	ReasonExfiltration    Reason = "exfiltration"     // exfiltration >= TaintAt
	ReasonGapScanLimit    Reason = "gap_scan_limit"   // otherwise clean, but content ran past the windows
	ReasonGapUnclassified Reason = "gap_unclassified" // otherwise clean, but a window got no answer
)

// Outcome is a screen's result: the decision, the composed scores, why,
// any gap in the classifier's coverage, and the legs the content raises.
// It carries no content.
type Outcome struct {
	Decision proto.ScreenDecision
	Scores   proto.Scores
	Reason   Reason
	Gap      proto.Gap
	// Raised holds the legs this content raises: Untrusted is the input's
	// source when the decision is not pass, and Sensitive is
	// SourceCredential when the composed credentials score is at or above
	// TaintAt, whatever question drove the decision.
	Raised proto.Legs
}

// jevScores are the production screen's merged answers, when any window
// answered.
type jevScores struct {
	injection, exfiltration, credentials float64
}

// classify is classifyContent over the injection and credentials scores.
func classify(injection, credentials float64) (proto.ScreenDecision, Reason) {
	switch {
	case injection >= DenyAt:
		return proto.ScreenDeny, ReasonInjectionDeny
	case injection >= TaintAt:
		return proto.ScreenEscalate, ReasonInjection
	case credentials >= TaintAt:
		return proto.ScreenEscalate, ReasonCredentials
	}
	return proto.ScreenPass, ReasonBelowThresholds
}

// composeOutcome merges the local scores with Jev's per question, so Jev can
// only raise a score, and decides.
//
// Injection and credentials follow composeScreen. Exfiltration then joins
// on the same TaintAt line and can only raise the outcome: an outcome
// already tainted keeps its reason (the first evidence wins), a pass
// becomes an escalate, and exfiltration alone never withholds. barmkin-mod
// has no local exfiltration score; a shim-supplied one composes like
// Jev's, which can only tighten.
//
// The gap applies last, and only to content that is not withheld: an
// otherwise clean outcome escalates with the gap as its reason, and a
// tainted one keeps its own reason. A gap needs Jev configured; without it
// nothing is claimed to be classified.
func composeOutcome(source proto.Source, local proto.Scores, jev *jevScores, gap proto.Gap) Outcome {
	scores := local
	if jev != nil {
		scores.Injection = max(scores.Injection, jev.injection)
		scores.Credentials = max(scores.Credentials, jev.credentials)
		scores.Exfiltration = max(scores.Exfiltration, jev.exfiltration)
	}
	decision, reason := classify(scores.Injection, scores.Credentials)
	if decision == proto.ScreenPass && scores.Exfiltration >= TaintAt {
		decision, reason = proto.ScreenEscalate, ReasonExfiltration
	}
	if decision == proto.ScreenDeny {
		gap = proto.GapNone
	}
	if gap != proto.GapNone && decision == proto.ScreenPass {
		decision, reason = proto.ScreenEscalate, gapReason(gap)
	}
	out := Outcome{Decision: decision, Scores: scores, Reason: reason, Gap: gap,
		Raised: proto.Legs{Untrusted: proto.SourceNone, Sensitive: proto.SourceNone}}
	if decision != proto.ScreenPass {
		out.Raised.Untrusted = source
	}
	if scores.Credentials >= TaintAt {
		out.Raised.Sensitive = proto.SourceCredential
	}
	return out
}

func gapReason(g proto.Gap) Reason {
	if g == proto.GapScanLimit {
		return ReasonGapScanLimit
	}
	return ReasonGapUnclassified
}

// classifierGap is classifierGapReason over a window plan. With Jev
// configured, content that runs past the last window has a scan-limit gap,
// and content longer than one window with a window that got no answer has
// an unclassified gap. Content that fits one window degrades to the local
// scores on a failure, as it does with no Jev configured, so it has no gap.
// A scan-limit gap is reported over an unclassified one: it holds whatever
// the endpoint does.
func classifierGap(configured, pastLastWindow bool, answered []bool) proto.Gap {
	if !configured {
		return proto.GapNone
	}
	if pastLastWindow {
		return proto.GapScanLimit
	}
	if len(answered) <= 1 {
		return proto.GapNone
	}
	for _, ok := range answered {
		if !ok {
			return proto.GapUnclassified
		}
	}
	return proto.GapNone
}
