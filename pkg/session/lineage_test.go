package session

import "testing"

func TestLineageEvidenceClearsOnTurnAdvanceButDerivedPathsPersist(t *testing.T) {
	state := NewState(t.TempDir())
	state.RecordLineageEvidence("sensitive_read", ".env", "high", []LineageLabel{
		{Sensitivity: "secret", Trust: "trusted", Provenance: "user"},
	})
	state.AttachActiveEvidenceToPath("/tmp/project/debug.txt")

	if got := len(state.ActiveEvidence); got != 1 {
		t.Fatalf("ActiveEvidence len = %d, want 1", got)
	}
	if got := state.DerivedLabelsForPath("/tmp/project/debug.txt"); len(got) != 1 {
		t.Fatalf("DerivedLabelsForPath before turn advance = %v, want 1 label", got)
	}

	state.IncrementTurn()

	if got := len(state.ActiveEvidence); got != 0 {
		t.Fatalf("ActiveEvidence len after turn advance = %d, want 0", got)
	}
	if got := state.DerivedLabelsForPath("/tmp/project/debug.txt"); len(got) != 1 {
		t.Fatalf("DerivedLabelsForPath after turn advance = %v, want lineage to persist", got)
	}
}
