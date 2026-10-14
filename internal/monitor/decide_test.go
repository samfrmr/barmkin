package monitor

import (
	"slices"
	"testing"

	"github.com/Daviey/barmkin/internal/proto"
)

var allClasses = []proto.Class{
	proto.ClassShellOutward, proto.ClassNetClient, proto.ClassDNS, proto.ClassForge,
	proto.ClassPublish, proto.ClassCloud, proto.ClassInterpreterNet, proto.ClassPersistShell,
	proto.ClassDestructive, proto.ClassHistoryRewrite, proto.ClassWebFetch, proto.ClassWebSearch,
	proto.ClassMonitorWS, proto.ClassMCPWrite, proto.ClassSkillLoad, proto.ClassPersistence,
}

func legsOf(untrusted, sensitive proto.Source) proto.Legs {
	return proto.Legs{Untrusted: untrusted, Sensitive: sensitive}
}

var (
	clean     = legsOf(proto.SourceNone, proto.SourceNone)
	untrusted = legsOf(proto.SourceFetch, proto.SourceNone)
	sensitive = legsOf(proto.SourceNone, proto.SourceCredential)
	both      = legsOf(proto.SourceMCP, proto.SourceCredential)
)

// Behaviour fixtures, from barmkin-mod's decideEgress (hooks/lib/egress.ts)
// and its EGRESS_CLASSES postures.
func TestDecideParity(t *testing.T) {
	cases := []struct {
		name    string
		classes []proto.Class
		legs    proto.Legs
		verdict proto.Verdict
		rule    proto.Rule
		named   []proto.Class
	}{
		{"no classes, clean", nil, clean, proto.VerdictPass, proto.RuleNone, nil},
		{"no classes, both legs", nil, both, proto.VerdictPass, proto.RuleNone, nil},
		{"egress in a clean session", []proto.Class{proto.ClassWebFetch, proto.ClassNetClient}, clean, proto.VerdictPass, proto.RuleNone, nil},
		{"destructive in a clean session warns",
			[]proto.Class{proto.ClassDNS, proto.ClassDestructive}, clean, proto.VerdictWarn, proto.RuleNone,
			[]proto.Class{proto.ClassDestructive}},
		{"history rewrite in a clean session warns",
			[]proto.Class{proto.ClassHistoryRewrite}, clean, proto.VerdictWarn, proto.RuleNone,
			[]proto.Class{proto.ClassHistoryRewrite}},
		{"sensitive alone is clean",
			[]proto.Class{proto.ClassWebFetch, proto.ClassDestructive}, sensitive, proto.VerdictWarn, proto.RuleNone,
			[]proto.Class{proto.ClassDestructive}},
		{"untrusted denies the deny classes only",
			[]proto.Class{proto.ClassDNS, proto.ClassWebFetch, proto.ClassForge, proto.ClassShellOutward}, untrusted,
			proto.VerdictDeny, proto.RuleUntrusted, []proto.Class{proto.ClassWebFetch, proto.ClassShellOutward}},
		{"untrusted warns on the warn classes",
			[]proto.Class{proto.ClassDNS, proto.ClassPersistence}, untrusted, proto.VerdictWarn, proto.RuleNone,
			[]proto.Class{proto.ClassDNS, proto.ClassPersistence}},
		{"untrusted denies destructive",
			[]proto.Class{proto.ClassDestructive}, untrusted, proto.VerdictDeny, proto.RuleUntrusted,
			[]proto.Class{proto.ClassDestructive}},
		{"rule of two denies every class",
			[]proto.Class{proto.ClassWebSearch, proto.ClassPersistence}, both, proto.VerdictDeny, proto.RuleRuleOfTwo,
			[]proto.Class{proto.ClassWebSearch, proto.ClassPersistence}},
		{"monitor-set sources count as untrusted",
			[]proto.Class{proto.ClassNetClient}, legsOf(proto.SourceMonitorRestart, proto.SourceNone),
			proto.VerdictDeny, proto.RuleUntrusted, []proto.Class{proto.ClassNetClient}},
		{"unknown session source with sensitive is the rule of two",
			[]proto.Class{proto.ClassDNS}, legsOf(proto.SourceUnknownSession, proto.SourceCredential),
			proto.VerdictDeny, proto.RuleRuleOfTwo, []proto.Class{proto.ClassDNS}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := decide(tc.classes, tc.legs)
			named := tc.named
			if named == nil {
				named = []proto.Class{}
			}
			if resp.Verdict != tc.verdict || resp.Rule != tc.rule || !slices.Equal(resp.Classes, named) || resp.Legs != tc.legs {
				t.Fatalf("decide = %+v, want %s %s %v", resp, tc.verdict, tc.rule, named)
			}
			if _, err := proto.Encode(&resp); err != nil {
				t.Fatalf("decide produced an invalid response: %+v", resp)
			}
		})
	}
}

func TestEveryClassHasAPosture(t *testing.T) {
	for _, c := range allClasses {
		if _, ok := classPostures[c]; !ok {
			t.Errorf("class %s has no posture", c)
		}
	}
	if len(classPostures) != len(allClasses) {
		t.Errorf("table has %d classes, contract has %d", len(classPostures), len(allClasses))
	}
}

// With the untrusted leg up, no class passes; with both legs up, every
// class is denied.
func TestTaintNeverPasses(t *testing.T) {
	for _, c := range allClasses {
		for _, legs := range []proto.Legs{untrusted, both} {
			resp := decide([]proto.Class{c}, legs)
			if resp.Verdict == proto.VerdictPass {
				t.Errorf("class %s passes with legs %+v", c, legs)
			}
		}
		if resp := decide([]proto.Class{c}, both); resp.Verdict != proto.VerdictDeny {
			t.Errorf("class %s not denied under the rule of two", c)
		}
	}
}

func TestUnlistedClassFailsClosed(t *testing.T) {
	future := proto.Class("teleport")
	if resp := decide([]proto.Class{future}, untrusted); resp.Verdict != proto.VerdictDeny {
		t.Errorf("an unlisted class under taint: %+v", resp)
	}
	if resp := decide([]proto.Class{future}, clean); resp.Verdict != proto.VerdictWarn {
		t.Errorf("an unlisted class when clean: %+v", resp)
	}
}
