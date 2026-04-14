package hooks

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/lease"
	mcppkg "github.com/somoore/sir/pkg/mcp"
	"github.com/somoore/sir/pkg/session"
)

// seedApprovedLeaseWithBinary writes a lease where serverName is approved
// with the command hash+mtime of the binary at binPath. Returns the lease.
func seedApprovedLeaseWithBinary(t *testing.T, projectRoot, serverName, binPath string) *lease.Lease {
	t.Helper()
	modTime, hash, err := mcppkg.StatCommand(binPath)
	if err != nil {
		t.Fatalf("stat binary: %v", err)
	}
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{serverName}
	l.MCPApprovals = map[string]lease.MCPApproval{
		serverName: {
			ApprovedAt:     time.Now().Add(-time.Hour),
			Command:        binPath,
			CommandHash:    hash,
			CommandModTime: modTime,
		},
	}
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	return l
}

func TestEvaluateMCPBinaryDrift_UnchangedAllows(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Disable onboarding gate so it doesn't mask the drift test result.
	writeOnboardingConfig(t, home, -1, -1)

	projectRoot := t.TempDir()
	binPath := filepath.Join(projectRoot, "mcp-bin")
	if err := os.WriteFile(binPath, []byte("stable content"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	l := seedApprovedLeaseWithBinary(t, projectRoot, "stable", binPath)
	state := newTestSession(t, projectRoot)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__stable__action",
		ToolInput: map[string]interface{}{},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("unchanged binary should allow, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluateMCPBinaryDrift_ContentChangeAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeOnboardingConfig(t, home, -1, -1)

	projectRoot := t.TempDir()
	binPath := filepath.Join(projectRoot, "mcp-bin")
	if err := os.WriteFile(binPath, []byte("original"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	l := seedApprovedLeaseWithBinary(t, projectRoot, "swap", binPath)

	// Overwrite the binary with different content AFTER approval. Force a
	// later mtime so mtime-equal fast path does not mask the hash change.
	if err := os.WriteFile(binPath, []byte("REPLACED"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(binPath, future, future); err != nil {
		t.Fatal(err)
	}

	state := newTestSession(t, projectRoot)
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__swap__action",
		ToolInput: map[string]interface{}{},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("content change should ask, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluateMCPBinaryDrift_MtimeOnlyChangeAllows(t *testing.T) {
	// If only mtime changes (touch, chmod), content is still the same.
	// The gate must NOT ask — doing so would be a false positive.
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeOnboardingConfig(t, home, -1, -1)

	projectRoot := t.TempDir()
	binPath := filepath.Join(projectRoot, "mcp-bin")
	if err := os.WriteFile(binPath, []byte("same bytes"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	l := seedApprovedLeaseWithBinary(t, projectRoot, "touched", binPath)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(binPath, future, future); err != nil {
		t.Fatal(err)
	}

	state := newTestSession(t, projectRoot)
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__touched__action",
		ToolInput: map[string]interface{}{},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("mtime-only change should allow, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluateMCPBinaryDrift_DeletedBinaryAsks(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeOnboardingConfig(t, home, -1, -1)

	projectRoot := t.TempDir()
	binPath := filepath.Join(projectRoot, "mcp-bin")
	if err := os.WriteFile(binPath, []byte("original"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	l := seedApprovedLeaseWithBinary(t, projectRoot, "gone", binPath)
	if err := os.Remove(binPath); err != nil {
		t.Fatal(err)
	}

	state := newTestSession(t, projectRoot)
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__gone__action",
		ToolInput: map[string]interface{}{},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Fatalf("deleted binary should ask, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluateMCPBinaryDrift_EmptyHashSkipped(t *testing.T) {
	// MCP approved with empty hash (npx/uvx/PATH-unresolvable). Drift gate
	// must not fire — documented limitation.
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeOnboardingConfig(t, home, -1, -1)

	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"viaNpx"}
	l.MCPApprovals = map[string]lease.MCPApproval{
		"viaNpx": {
			ApprovedAt: time.Now().Add(-time.Hour),
			Command:    "npx",
			// CommandHash intentionally empty.
		},
	}
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}

	state := newTestSession(t, projectRoot)
	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "mcp__viaNpx__action",
		ToolInput: map[string]interface{}{},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("empty-hash approval should skip drift gate; got %q", resp.Decision)
	}
}
