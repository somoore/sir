package main

import "testing"

func TestTopLevelCommands_NonEmpty(t *testing.T) {
	if len(topLevelCommands) < 10 {
		t.Fatalf("expected a substantial command list, got %d", len(topLevelCommands))
	}
	// Spot-check a few that must be completable.
	want := map[string]bool{"install": true, "status": true, "approve": true, "why": true}
	for _, c := range topLevelCommands {
		delete(want, c)
	}
	if len(want) != 0 {
		t.Errorf("completion list missing commands: %v", want)
	}
}
