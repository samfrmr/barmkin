package monitor

import "github.com/Daviey/barmkin/internal/proto"

// posture is what one egress class does in a session.
type posture struct {
	denyOnUntrusted bool // the untrusted leg alone denies it; otherwise it warns
	warnWhenClean   bool // it warns even with the untrusted leg down
}

// classPostures is the class postures table, versioned with the monitor.
// It matches barmkin-mod's EGRESS_CLASSES (hooks/lib/egress.ts): only the
// destructive classes warn in a clean session, and both legs up deny every
// class.
var classPostures = map[proto.Class]posture{
	proto.ClassShellOutward:   {denyOnUntrusted: true},
	proto.ClassNetClient:      {denyOnUntrusted: true},
	proto.ClassDNS:            {},
	proto.ClassForge:          {},
	proto.ClassPublish:        {},
	proto.ClassCloud:          {},
	proto.ClassInterpreterNet: {denyOnUntrusted: true},
	proto.ClassPersistShell:   {},
	proto.ClassDestructive:    {denyOnUntrusted: true, warnWhenClean: true},
	proto.ClassHistoryRewrite: {denyOnUntrusted: true, warnWhenClean: true},
	proto.ClassWebFetch:       {denyOnUntrusted: true},
	proto.ClassWebSearch:      {},
	proto.ClassMonitorWS:      {denyOnUntrusted: true},
	proto.ClassMCPWrite:       {denyOnUntrusted: true},
	proto.ClassSkillLoad:      {denyOnUntrusted: true},
	proto.ClassPersistence:    {},
}

// decide is the verdict for a call in classes, in a lineage with legs. It
// mirrors barmkin-mod's decideEgress:
//   - no classes, or a clean untrusted leg with no destructive class: pass;
//   - untrusted leg down: warn on the destructive classes only;
//   - both legs up: deny every class (the Rule of Two);
//   - untrusted leg up: deny the classes that deny on it, else warn on all.
//
// The sensitive leg alone changes nothing; it denies only with the untrusted
// leg. A class missing from the table denies on any taint and warns when
// clean, so a newer vocabulary can never pass by default.
func decide(classes []proto.Class, legs proto.Legs) proto.DecideResponse {
	resp := proto.DecideResponse{
		Version: proto.Version,
		Verdict: proto.VerdictPass,
		Rule:    proto.RuleNone,
		Classes: []proto.Class{},
		Legs:    legs,
	}
	if len(classes) == 0 {
		return resp
	}
	lookup := func(c proto.Class) posture {
		p, ok := classPostures[c]
		if !ok {
			return posture{denyOnUntrusted: true, warnWhenClean: true}
		}
		return p
	}
	pick := func(keep func(posture) bool) []proto.Class {
		out := []proto.Class{}
		for _, c := range classes {
			if keep(lookup(c)) {
				out = append(out, c)
			}
		}
		return out
	}

	switch {
	case legs.Untrusted == proto.SourceNone:
		if advisory := pick(func(p posture) bool { return p.warnWhenClean }); len(advisory) > 0 {
			resp.Verdict, resp.Classes = proto.VerdictWarn, advisory
		}
	case legs.Sensitive != proto.SourceNone:
		resp.Verdict, resp.Rule, resp.Classes = proto.VerdictDeny, proto.RuleRuleOfTwo, pick(func(posture) bool { return true })
	default:
		if denied := pick(func(p posture) bool { return p.denyOnUntrusted }); len(denied) > 0 {
			resp.Verdict, resp.Rule, resp.Classes = proto.VerdictDeny, proto.RuleUntrusted, denied
		} else {
			resp.Verdict, resp.Classes = proto.VerdictWarn, pick(func(posture) bool { return true })
		}
	}
	return resp
}
