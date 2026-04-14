package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// writeConfig is a test helper that writes ~/.sir/config.json with the
// provided fields. Caller must have already pointed HOME at a temp dir.
func writeOnboardingConfig(t *testing.T, home string, windowHours, callCount int) {
	t.Helper()
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"mcp_trust_posture":            "standard",
		"mcp_onboarding_window_hours":  windowHours,
		"mcp_onboarding_call_count":    callCount,
	}
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// seedApprovedLease writes a lease with one approved MCP server whose
// MCPApprovals record was timestamped `age` ago.
func seedApprovedLease(t *testing.T, projectRoot, serverName string, approvedAt time.Time) *lease.Lease {
	t.Helper()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{serverName}
	l.MCPApprovals = map[string]lease.MCPApproval{
		serverName: {ApprovedAt: approvedAt},
	}
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestEvaluateMCPOnboarding_FirstCallAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 24, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Hour))
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("expected ask during onboarding window, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
	// Counter must have incremented so the gate knows progress was made.
	if got := state.MCPOnboardingCallCount("fresh"); got != 1 {
		t.Fatalf("counter = %d, want 1", got)
	}
}

func TestEvaluateMCPOnboarding_CountThresholdEndsGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 24, 3)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Minute))
	state := newTestSession(t, projectRoot)
	// Pre-seed the counter as if three calls already happened this session.
	for i := 0; i < 3; i++ {
		state.BumpMCPOnboardingCall("fresh")
	}
	// Re-save so SessionHash matches the mutated state; otherwise the
	// integrity guard denies the next evaluation.
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow after count threshold, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
	// Counter must NOT have been bumped — we never entered the gate.
	if got := state.MCPOnboardingCallCount("fresh"); got != 3 {
		t.Fatalf("counter = %d, expected unchanged at 3", got)
	}
}

func TestEvaluateMCPOnboarding_WallClockWindowEndsGate(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 1, 100)
	// Approved 2 hours ago — outside the 1h window.
	l := seedApprovedLease(t, projectRoot, "old", time.Now().Add(-2*time.Hour))
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__old__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow after window close, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluateMCPOnboarding_NegativeDisables(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, -1, 20)
	l := seedApprovedLease(t, projectRoot, "fresh", time.Now().Add(-1*time.Minute))
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__fresh__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow with gate disabled, got %q", resp.Decision)
	}
}

func TestEvaluateMCPOnboarding_GrandfatheredApprovalSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 24, 20)
	// No MCPApprovals record — simulates a pre-upgrade approval.
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"legacy"}
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__legacy__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow for grandfathered approval (no record), got %q", resp.Decision)
	}
}

func TestEvaluateMCPOnboarding_UnapprovedServerUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 24, 20)
	// No approved list — server is unknown.
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__stranger__action",
		ToolInput: map[string]interface{}{"x": 1},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("unapproved MCP server should ask via mcp_unapproved, got %q", resp.Decision)
	}
}

func TestEvaluateMCPOnboarding_NonMCPToolUntouched(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()

	writeOnboardingConfig(t, home, 24, 20)
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": filepath.Join(projectRoot, "readme.md")},
		CWD:       projectRoot,
	}, lease.DefaultLease(), state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("Read should not be touched by onboarding gate, got %q", resp.Decision)
	}
	if got := state.MCPOnboardingCallCount("anything"); got != 0 {
		t.Fatalf("onboarding counter mutated for non-MCP tool: %d", got)
	}
}
