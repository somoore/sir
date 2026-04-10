package hooks

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// InstructionSource describes where an instruction file came from.
type InstructionSource struct {
	Path       string
	Provenance string // "repo_content", "user", "mcp_tool"
}

// HandleInstructionLoad processes a Notification hook for instruction file loading.
// Logs the instruction file to the ledger with its provenance and content hash.
func HandleInstructionLoad(source InstructionSource, projectRoot string) error {
	// Compute content hash (never store content itself)
	data, err := os.ReadFile(source.Path)
	if err != nil {
		// File may not exist yet or be unreadable — log with empty hash
		data = nil
	}

	contentHash := ""
	if data != nil {
		h := sha256.Sum256(data)
		contentHash = fmt.Sprintf("%x", h)
	}

	entry := &ledger.Entry{
		ToolName:    "Notification",
		Verb:        "instruction_load",
		Target:      source.Path,
		Provenance:  source.Provenance,
		Decision:    "allow",
		Reason:      "instruction file loaded",
		ContentHash: contentHash,
	}

	return ledger.Append(projectRoot, entry)
}

// --- Tests ---

func TestInstructions_RepoFile(t *testing.T) {
	projectRoot := t.TempDir()
	// Set HOME so session.StateDir resolves correctly
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Create project state dir so ledger can write
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Create a CLAUDE.md in the repo
	claudeFile := filepath.Join(projectRoot, "CLAUDE.md")
	os.WriteFile(claudeFile, []byte("# Repo instructions\nDo this."), 0o644)

	source := InstructionSource{
		Path:       claudeFile,
		Provenance: "repo_content",
	}

	err := HandleInstructionLoad(source, projectRoot)
	if err != nil {
		t.Fatalf("HandleInstructionLoad: %v", err)
	}

	// Read back from ledger
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 ledger entry, got %d", len(entries))
	}

	e := entries[0]
	if e.Verb != "instruction_load" {
		t.Errorf("expected verb instruction_load, got %q", e.Verb)
	}
	if e.Provenance != "repo_content" {
		t.Errorf("expected provenance repo_content, got %q", e.Provenance)
	}
	if e.Target != claudeFile {
		t.Errorf("expected target %q, got %q", claudeFile, e.Target)
	}
}

func TestInstructions_UserFile(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Create a user-level instruction file
	userFile := filepath.Join(tmpHome, ".claude", "CLAUDE.md")
	os.MkdirAll(filepath.Dir(userFile), 0o755)
	os.WriteFile(userFile, []byte("# User instructions"), 0o644)

	source := InstructionSource{
		Path:       userFile,
		Provenance: "user",
	}

	err := HandleInstructionLoad(source, projectRoot)
	if err != nil {
		t.Fatalf("HandleInstructionLoad: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	if entries[0].Provenance != "user" {
		t.Errorf("expected provenance 'user', got %q", entries[0].Provenance)
	}
}

func TestInstructions_HashComputed(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	content := "# Test instructions with known content"
	testFile := filepath.Join(projectRoot, "CLAUDE.md")
	os.WriteFile(testFile, []byte(content), 0o644)

	source := InstructionSource{
		Path:       testFile,
		Provenance: "repo_content",
	}

	err := HandleInstructionLoad(source, projectRoot)
	if err != nil {
		t.Fatalf("HandleInstructionLoad: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}

	// Verify the content hash matches
	expected := sha256.Sum256([]byte(content))
	expectedHash := fmt.Sprintf("%x", expected)
	if entries[0].ContentHash != expectedHash {
		t.Errorf("content hash mismatch: got %q, want %q", entries[0].ContentHash, expectedHash)
	}
}

func TestInstructions_NonExistentFile(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	source := InstructionSource{
		Path:       filepath.Join(projectRoot, "nonexistent.md"),
		Provenance: "repo_content",
	}

	// Should not error — just log with empty content hash
	err := HandleInstructionLoad(source, projectRoot)
	if err != nil {
		t.Fatalf("HandleInstructionLoad should not error for nonexistent file: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].ContentHash != "" {
		t.Errorf("expected empty content hash for nonexistent file, got %q", entries[0].ContentHash)
	}
}

func TestInstructions_LedgerNeverStoresContent(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	secretContent := "API_KEY=sk-super-secret-value\nDB_PASSWORD=hunter2"
	testFile := filepath.Join(projectRoot, "instructions.md")
	os.WriteFile(testFile, []byte(secretContent), 0o644)

	source := InstructionSource{
		Path:       testFile,
		Provenance: "repo_content",
	}

	HandleInstructionLoad(source, projectRoot)

	// Read raw ledger file to verify no secret content leaked
	ledgerPath := ledger.LedgerPath(projectRoot)
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	ledgerStr := string(data)
	if containsAny(ledgerStr, "sk-super-secret-value", "hunter2") {
		t.Error("ledger file contains secret content — SECURITY BUG")
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
