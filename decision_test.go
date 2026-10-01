package main

import "testing"

func TestRenderEscalateJSON(t *testing.T) {
	got := renderEscalateJSON("semantic check: no_outward_effect (p=0.07)")
	want := `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"semantic check: no_outward_effect (p=0.07)"}}`
	if got != want {
		t.Errorf("got %s\nwant %s", got, want)
	}
}

func TestDecision_String(t *testing.T) {
	cases := []struct {
		d    Decision
		want string
	}{
		{Pass, "allow"},
		{Escalate, "escalate"},
		{Deny, "deny"},
	}
	for _, tc := range cases {
		if got := tc.d.String(); got != tc.want {
			t.Errorf("Decision(%d).String() = %q, want %q", tc.d, got, tc.want)
		}
	}
}
