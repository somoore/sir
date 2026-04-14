package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func TestLoadLease_AutoApprovesDiscoveredMCPServers(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"paper":{"command":"node","args":["paper.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadLease(projectRoot)
	if err != nil {
		t.Fatalf("loadLease: %v", err)
	}
	if !containsStringValue(loaded.ApprovedMCPServers, "paper") {
		t.Fatalf("expected discovered MCP server to be auto-approved, got %v", loaded.ApprovedMCPServers)
	}

	reloaded, err := lease.Load(filepath.Join(stateDir, "lease.json"))
	if err != nil {
		t.Fatalf("reload persisted lease: %v", err)
	}
	if !containsStringValue(reloaded.ApprovedMCPServers, "paper") {
		t.Fatalf("expected refreshed approval to persist to lease.json, got %v", reloaded.ApprovedMCPServers)
	}
}

func TestEvaluatePayload_AutoApprovedDiscoveredMCPServerAvoidsUnknownPrompt(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"paper":{"command":"node","args":["paper.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}

	state := newTestSession(t, projectRoot)
	loaded, err := loadLease(projectRoot)
	if err != nil {
		t.Fatalf("loadLease: %v", err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName: "mcp__paper__write_html",
		ToolInput: map[string]interface{}{
			"html": "<div>hello</div>",
		},
		CWD: projectRoot,
	}, loaded, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected discovered MCP server call to bypass mcp_unapproved ask, got %q (reason=%s)", resp.Decision, resp.Reason)
	}
}

func TestLoadLease_ManagedModeDoesNotAutoApproveDiscoveredMCPServers(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"paper":{"command":"node","args":["paper.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	managedLease := lease.DefaultLease()
	manifestPath := writeManagedPolicyManifest(t, tmpHome, managedLease)
	t.Setenv(session.ManagedPolicyPathEnvVar, manifestPath)

	loaded, err := loadLease(projectRoot)
	if err != nil {
		t.Fatalf("loadLease: %v", err)
	}
	if containsStringValue(loaded.ApprovedMCPServers, "paper") {
		t.Fatalf("managed policy should pin approved_mcp_servers, got %v", loaded.ApprovedMCPServers)
	}
}

func TestLoadLease_AutoApprovesDiscoveredClaudeLegacyMCPServers(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpHome, ".claude.json"), []byte(`{"mcpServers":{"HopperMCPServer":{"command":"node","args":["hopper.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}

	loaded, err := loadLease(projectRoot)
	if err != nil {
		t.Fatalf("loadLease: %v", err)
	}
	if !containsStringValue(loaded.ApprovedMCPServers, "HopperMCPServer") {
		t.Fatalf("expected Claude legacy MCP server to be auto-approved, got %v", loaded.ApprovedMCPServers)
	}
}

func TestLoadOrCreateSession_AdoptsSirRefreshedLeaseHash(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpHome, ".claude.json"), []byte(`{"mcpServers":{"HopperMCPServer":{"command":"node","args":["hopper.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	oldHash, err := hashLeaseFile(projectRoot)
	if err != nil {
		t.Fatalf("hash original lease: %v", err)
	}

	state := session.NewState(projectRoot)
	state.LeaseHash = oldHash
	if err := state.Save(); err != nil {
		t.Fatalf("save session: %v", err)
	}

	loaded, meta, err := loadLeaseWithMetadata(projectRoot)
	if err != nil {
		t.Fatalf("loadLeaseWithMetadata: %v", err)
	}
	if !meta.refreshedBySir {
		t.Fatalf("expected sir-driven lease refresh, got %+v", meta)
	}

	reloadedState, err := loadOrCreateSession(projectRoot, loaded, meta)
	if err != nil {
		t.Fatalf("loadOrCreateSession: %v", err)
	}
	if reloadedState.LeaseHash != meta.currentHash {
		t.Fatalf("state lease hash = %q, want %q", reloadedState.LeaseHash, meta.currentHash)
	}
	if !VerifyLeaseIntegrity(projectRoot, reloadedState) {
		t.Fatal("expected refreshed session lease hash to pass integrity verification")
	}
	if !session.VerifySessionIntegrity(reloadedState) {
		t.Fatal("expected refreshed session to remain internally consistent")
	}
}

func writeManagedPolicyManifest(t *testing.T, dir string, l *lease.Lease) string {
	t.Helper()

	leaseHash, err := session.HashManagedLease(l)
	if err != nil {
		t.Fatalf("HashManagedLease: %v", err)
	}
	managedHooks := json.RawMessage(`{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"/usr/local/bin/sir guard evaluate"}]}]}`)
	hookHash, err := session.HashManagedHooksSubtree(managedHooks)
	if err != nil {
		t.Fatalf("HashManagedHooksSubtree: %v", err)
	}

	manifest := map[string]interface{}{
		"managed":            true,
		"policy_version":     "test-policy",
		"managed_lease":      l,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": managedHooks,
		},
		"managed_hook_hashes": map[string]string{
			"claude": hookHash,
		},
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}

	path := filepath.Join(dir, "managed-policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write managed policy: %v", err)
	}
	return path
}

func containsStringValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
