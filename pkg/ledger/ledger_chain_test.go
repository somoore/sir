package ledger

import (
	"fmt"
	"os"
	"testing"

	"github.com/somoore/sir/pkg/session"
)

// setupTestProject creates a temp project root and ensures the
// sir state directory exists for it.
func setupTestProject(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	stateDir := session.StateDir(tmpDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("failed to create state dir: %v", err)
	}
	return tmpDir
}

func TestAppendAndReadEntries(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry1 := &Entry{
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      "src/main.go",
		Sensitivity: "internal",
		Trust:       "trusted",
		Provenance:  "user",
		Decision:    "allow",
		Reason:      "within lease boundary",
	}
	if err := Append(projectRoot, entry1); err != nil {
		t.Fatalf("append first entry: %v", err)
	}

	entry2 := &Entry{
		ToolName:    "Bash",
		Verb:        "net_external",
		Target:      "https://evil.com/collect",
		Sensitivity: "secret",
		Trust:       "trusted",
		Provenance:  "user",
		Decision:    "deny",
		Reason:      "session carries secret-labeled data, sink is untrusted",
		Severity:    "HIGH",
	}
	if err := Append(projectRoot, entry2); err != nil {
		t.Fatalf("append second entry: %v", err)
	}

	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Index != 0 {
		t.Errorf("first entry index = %d, want 0", entries[0].Index)
	}
	if entries[1].Index != 1 {
		t.Errorf("second entry index = %d, want 1", entries[1].Index)
	}
	if entries[0].ToolName != "Read" {
		t.Errorf("first entry tool = %q, want Read", entries[0].ToolName)
	}
	if entries[1].Decision != "deny" {
		t.Errorf("second entry decision = %q, want deny", entries[1].Decision)
	}
}

func TestHashChainIntegrity(t *testing.T) {
	projectRoot := setupTestProject(t)

	for i := 0; i < 5; i++ {
		entry := &Entry{
			ToolName: "Read",
			Verb:     "read_ref",
			Target:   fmt.Sprintf("file%d.go", i),
			Decision: "allow",
			Reason:   "within lease boundary",
		}
		if err := Append(projectRoot, entry); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if count != 5 {
		t.Errorf("verified %d entries, want 5", count)
	}

	// Verify genesis prev_hash
	entries, _ := ReadAll(projectRoot)
	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	if entries[0].PrevHash != genesis {
		t.Errorf("genesis prev_hash = %q, want %q", entries[0].PrevHash, genesis)
	}

	// Verify chain links
	for i := 1; i < len(entries); i++ {
		if entries[i].PrevHash != entries[i-1].EntryHash {
			t.Errorf("chain broken at entry %d: prev_hash=%q, previous entry_hash=%q",
				i, entries[i].PrevHash, entries[i-1].EntryHash)
		}
	}
}
