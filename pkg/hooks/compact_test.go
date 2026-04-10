package hooks

import (
	"os"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/session"
)

// CompactReminder generates a context reminder for the Compact (context window
// compaction) hook. This is injected when Claude Code compacts the conversation
// so that security-relevant session state is not lost.
func CompactReminder(state *session.State) string {
	if state == nil {
		return ""
	}

	var parts []string

	if state.DenyAll {
		parts = append(parts, "sir EMERGENCY: Session is in deny-all mode. ALL tool calls are blocked. Reason: "+state.DenyAllReason+". Run `sir doctor` in a new terminal.")
	}

	if state.SecretSession {
		scope := state.ApprovalScope
		if scope == "" {
			scope = "session"
		}
		parts = append(parts, "sir: This session carries SECRET data (scope: "+string(scope)+"). External network requests are blocked. Run `sir unlock` to lift.")
	}

	// Tainted MCP servers would be tracked in session state if we had that field.
	// For now, check RecentlyReadUntrusted as a proxy for elevated posture.
	if state.RecentlyReadUntrusted {
		parts = append(parts, "sir: Elevated posture — untrusted content was recently read. Agent delegation and MCP calls may require approval.")
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n")
}

// --- Tests ---

func TestCompact_SecretSession(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkSecretSession()

	reminder := CompactReminder(state)
	if reminder == "" {
		t.Fatal("expected non-empty reminder for secret session")
	}
	if !strings.Contains(reminder, "SECRET") {
		t.Errorf("reminder should mention SECRET, got: %s", reminder)
	}
	if !strings.Contains(reminder, "sir unlock") {
		t.Errorf("reminder should mention sir unlock, got: %s", reminder)
	}
}

func TestCompact_ElevatedPosture(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkUntrustedRead()

	reminder := CompactReminder(state)
	if reminder == "" {
		t.Fatal("expected non-empty reminder for elevated posture")
	}
	if !strings.Contains(reminder, "Elevated posture") {
		t.Errorf("reminder should mention elevated posture, got: %s", reminder)
	}
}

func TestCompact_DenyAll(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.SetDenyAll("hooks.json was tampered")

	reminder := CompactReminder(state)
	if reminder == "" {
		t.Fatal("expected non-empty reminder for deny-all session")
	}
	if !strings.Contains(reminder, "EMERGENCY") {
		t.Errorf("reminder should contain EMERGENCY, got: %s", reminder)
	}
	if !strings.Contains(reminder, "deny-all") {
		t.Errorf("reminder should mention deny-all, got: %s", reminder)
	}
	if !strings.Contains(reminder, "sir doctor") {
		t.Errorf("reminder should mention sir doctor, got: %s", reminder)
	}
}

func TestCompact_TaintedServers(t *testing.T) {
	// Currently we use RecentlyReadUntrusted as proxy for tainted state.
	// When tainted MCP server tracking is added to session, this test should
	// be updated to use the real field.
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkUntrustedRead()

	reminder := CompactReminder(state)
	if !strings.Contains(reminder, "untrusted") {
		t.Errorf("reminder should mention untrusted content, got: %s", reminder)
	}
}

func TestCompact_CleanSession(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	reminder := CompactReminder(state)
	if reminder != "" {
		t.Errorf("expected empty reminder for clean session, got: %q", reminder)
	}
}

func TestCompact_NoSession(t *testing.T) {
	reminder := CompactReminder(nil)
	if reminder != "" {
		t.Errorf("expected empty reminder for nil session, got: %q", reminder)
	}
}

func TestCompact_MultipleFlags(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkSecretSession()
	state.MarkUntrustedRead()

	reminder := CompactReminder(state)
	if !strings.Contains(reminder, "SECRET") {
		t.Error("reminder should mention SECRET")
	}
	if !strings.Contains(reminder, "Elevated posture") {
		t.Error("reminder should mention elevated posture")
	}
	// Should be multi-line
	lines := strings.Split(reminder, "\n")
	if len(lines) < 2 {
		t.Errorf("expected at least 2 lines for multiple flags, got %d", len(lines))
	}
}

func TestCompact_DenyAllWithSecretSession(t *testing.T) {
	// deny-all should take priority in output ordering
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkSecretSession()
	state.SetDenyAll("tamper detected")

	reminder := CompactReminder(state)
	// EMERGENCY should appear first
	emergencyIdx := strings.Index(reminder, "EMERGENCY")
	secretIdx := strings.Index(reminder, "SECRET")
	if emergencyIdx < 0 {
		t.Fatal("missing EMERGENCY")
	}
	if secretIdx < 0 {
		t.Fatal("missing SECRET")
	}
	if emergencyIdx > secretIdx {
		t.Error("EMERGENCY should appear before SECRET in reminder")
	}
}
