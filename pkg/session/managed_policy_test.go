package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

func TestLoadManagedPolicyValidatesManifest(t *testing.T) {
	policyPath := filepath.Join(t.TempDir(), "managed-policy.json")
	t.Setenv(ManagedPolicyPathEnvVar, policyPath)

	managedLease := lease.DefaultLease()
	leaseHash, err := HashManagedLease(managedLease)
	if err != nil {
		t.Fatalf("HashManagedLease: %v", err)
	}
	hooks := json.RawMessage(`{"PreToolUse":[{"matcher":".*","hooks":[{"command":"sir guard evaluate"}]}]}`)
	hookHash, err := HashManagedHooksSubtree(hooks)
	if err != nil {
		t.Fatalf("HashManagedHooksSubtree: %v", err)
	}

	doc := map[string]interface{}{
		"managed":            true,
		"policy_version":     "2026-04-09",
		"managed_lease":      managedLease,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": hooks,
		},
		"managed_hook_hashes": map[string]string{
			"claude": hookHash,
		},
		"disabled_local_commands": []string{"allow-host", "allow-remote", "trust"},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.WriteFile(policyPath, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	policy, err := LoadManagedPolicy()
	if err != nil {
		t.Fatalf("LoadManagedPolicy: %v", err)
	}
	if !policy.IsLocalCommandDisabled("allow-host") {
		t.Fatal("expected allow-host to be disabled by managed policy")
	}
	if policy.ManagedPolicySourcePath() != policyPath {
		t.Fatalf("policy path = %q, want %q", policy.ManagedPolicySourcePath(), policyPath)
	}
}
