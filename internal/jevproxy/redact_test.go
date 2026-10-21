package jevproxy

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestSecretRedactsNonEmpty(t *testing.T) {
	s := Secret("sk-or-v1-verysecret")
	for _, got := range []string{
		s.String(),
		fmt.Sprintf("%v", s),
		fmt.Sprintf("%s", s),
		fmt.Sprintf("%q", s),
		fmt.Sprintf("%+v", s),
		s.GoString(),
	} {
		if got == string(s) {
			t.Fatalf("formatting leaked the secret: %q", got)
		}
	}
	if s.Value() != "sk-or-v1-verysecret" {
		t.Errorf("Value() = %q, want the unwrapped secret", s.Value())
	}
}

func TestSecretEmptyFormatsEmpty(t *testing.T) {
	var s Secret
	if got := s.String(); got != "" {
		t.Errorf("empty Secret.String() = %q, want empty (matching screen.Credential)", got)
	}
}

func TestSecretMarshalTextRedacts(t *testing.T) {
	type wrapper struct{ Key Secret }
	data, err := json.Marshal(wrapper{Key: "sk-or-v1-verysecret"})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"Key":"[REDACTED]"}` {
		t.Errorf("marshaled = %s, want the key redacted", data)
	}
}
