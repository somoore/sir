package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// A second identical blocked/asked intent in a session should surface the
// repeated_denied_intent detection in real time (not just in the friction
// report), so routing and explain can react while the session is live.
func TestRepeatedIntent_DetectionFiresOnSecondBlock(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": ".claude/settings.json"},
		CWD:       projectRoot,
	}

	if _, err := evaluatePayload(payload, l, state, projectRoot); err != nil {
		t.Fatalf("first evaluate: %v", err)
	}
	first := lastDecision(t, projectRoot)
	if first.DetectionID == "repeated_denied_intent" {
		t.Fatalf("first occurrence must not be flagged repeated: %+v", first)
	}

	if _, err := evaluatePayload(payload, l, state, projectRoot); err != nil {
		t.Fatalf("second evaluate: %v", err)
	}
	second := lastDecision(t, projectRoot)
	if second.DetectionID != "repeated_denied_intent" {
		t.Errorf("second identical block: detection = %q, want repeated_denied_intent", second.DetectionID)
	}
}

func TestRecordPromptedIntent_CountsPerIntent(t *testing.T) {
	projectRoot := t.TempDir()
	state := newTestSession(t, projectRoot)
	k := promptKey("net_external", "https://a.example")
	if n := state.RecordPromptedIntent(k); n != 1 {
		t.Errorf("first record = %d, want 1", n)
	}
	if n := state.RecordPromptedIntent(k); n != 2 {
		t.Errorf("second record = %d, want 2", n)
	}
	if n := state.PromptCount(k); n != 2 {
		t.Errorf("PromptCount = %d, want 2", n)
	}
	if n := state.PromptCount(promptKey("net_external", "https://other.example")); n != 0 {
		t.Errorf("distinct intent count = %d, want 0", n)
	}
}
