package screen

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"testing"
)

// The pins barmkin-mod's tests/jev-questions.test.ts carries. A change to a
// question, the shared instruction or a wording arm changes a hash and fails
// here, so it is a reviewed edit made on both sides at once.
const (
	pinnedQuestionSetSHA256   = "41d0747f087e7db364e87ea9c46467086c6b8a457fcea748d4bbc19967cce11b"
	pinnedProductionSetSHA256 = "8a70c96e92d94604a1c4a453ec99836fe17777974503cb081176525f022dbe73"
)

func TestQuestionSetPinned(t *testing.T) {
	sum := sha256.Sum256([]byte(CanonicalQuestionSet()))
	if got := hex.EncodeToString(sum[:]); got != pinnedQuestionSetSHA256 {
		t.Fatalf("question set SHA-256 = %s, want the pinned %s", got, pinnedQuestionSetSHA256)
	}
	if ProductionQuestions.SHA256 != pinnedProductionSetSHA256 {
		t.Fatalf("production set SHA-256 = %s, want the pinned %s", ProductionQuestions.SHA256, pinnedProductionSetSHA256)
	}
}

func TestQuestionSets(t *testing.T) {
	if !slices.Equal(ProductionQuestions.IDs, []string{"injection", "exfiltration", "credentials"}) {
		t.Errorf("production asks %v", ProductionQuestions.IDs)
	}
	if _, ok := ProductionQuestions.Instructions[QuestionDestructive]; ok {
		t.Error("destructive_command reached production")
	}
	if got := ShadowQuestions(ArmCaptain).IDs; !slices.Equal(got, ScreenQuestionIDs) {
		t.Errorf("captain arm asks %v", got)
	}
	if got := ShadowQuestions(ArmRevised).IDs; !slices.Equal(got, []string{"destructive_command"}) {
		t.Errorf("revised arm asks %v", got)
	}
	if ShadowQuestions("settings") != nil {
		t.Error("an unknown arm has questions")
	}
	sets := []*QuestionSet{ProductionQuestions, ShadowQuestions(ArmCaptain), ShadowQuestions(ArmRevised)}
	seen := map[string]bool{}
	for _, qs := range sets {
		if seen[qs.SHA256] {
			t.Errorf("two question sets share a namespace %s", qs.SHA256)
		}
		seen[qs.SHA256] = true
		for _, id := range qs.IDs {
			text := qs.Instructions[id]
			if len(text) <= 100 || len(text) > 2048 {
				t.Errorf("%s/%s instructions are %d bytes", qs.name, id, len(text))
			}
			if !strings.Contains(text, "screening untrusted content") || strings.Count(text, "\n\n") != 1 {
				t.Errorf("%s/%s does not carry the shared instruction once", qs.name, id)
			}
		}
	}
}
