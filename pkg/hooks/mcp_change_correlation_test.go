package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/lease"
)

// After an MCP trust change (drift) is recorded, a privileged action in the
// same session is stamped with the compound mcp_change_then_privileged_use
// detection — even when the action itself is allowed.
func TestMCPChangeThenPrivilegedUse_StampedAtRuntime(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	// Simulate the drift guard having recorded an authority change.
	state.RecordMCPAuthorityChange()
	if err := state.Save(); err != nil { // persist so VerifySessionIntegrity passes
		t.Fatalf("save state: %v", err)
	}

	pre := &HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "curl https://api.demo.example/x"},
		CWD:       projectRoot,
	}
	if _, err := evaluatePayload(pre, l, state, projectRoot); err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	entry := lastDecision(t, projectRoot)
	if entry.DetectionID != string(detect.MCPChangeThenPrivilegedUse) {
		t.Fatalf("expected mcp_change_then_privileged_use, got %q (verb=%s decision=%s)", entry.DetectionID, entry.Verb, entry.Decision)
	}
}

// A routine read after an MCP trust change must NOT be flagged — the compound
// detection is scoped to privileged authority use.
func TestMCPChange_RoutineReadNotFlagged(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	state.RecordMCPAuthorityChange()
	if err := state.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	pre := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "src/main.go"},
		CWD:       projectRoot,
	}
	if _, err := evaluatePayload(pre, l, state, projectRoot); err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if entry := lastDecision(t, projectRoot); entry.DetectionID == string(detect.MCPChangeThenPrivilegedUse) {
		t.Errorf("routine read should not be flagged as compound MCP detection: %+v", entry)
	}
}
