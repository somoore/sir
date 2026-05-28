package main

import (
	"testing"

	"github.com/somoore/sir/pkg/ledger"
)

func TestRecordUninstall_WritesLedgerMarker(t *testing.T) {
	projectRoot := t.TempDir()
	t.Setenv("SIR_STATE_HOME", projectRoot)

	recordUninstall(projectRoot, "claude")

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Verb == "sir_uninstall" && e.Target == "claude" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected sir_uninstall ledger marker, got %d entries", len(entries))
	}
}
