package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func TestManagedModeRestoreUsesManifestWhenCanonicalMissing(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	leaseHash, err := session.HashManagedLease(l)
	if err != nil {
		t.Fatal(err)
	}
	managedHooks := json.RawMessage(`{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"/usr/local/bin/sir guard evaluate --agent claude"}]}]}`)
	hookHash, err := session.HashManagedHooksSubtree(managedHooks)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]interface{}{
		"managed":            true,
		"policy_version":     "2026-04-09",
		"managed_lease":      l,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": managedHooks,
		},
		"managed_hook_hashes": map[string]string{
			"claude": hookHash,
		},
		"disabled_local_commands": []string{"allow-host", "allow-remote", "trust"},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(tmpHome, "managed-policy.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(session.ManagedPolicyPathEnvVar, manifestPath)

	livePath := filepath.Join(claudeDir, "settings.json")
	if err := os.WriteFile(livePath, []byte(`{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"evil guard evaluate"}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 {
		t.Fatalf("expected 1 changed hook file, got %d: %+v", len(changed), changed)
	}
	if !AutoRestoreAgentHookFile(changed[0]) {
		t.Fatal("AutoRestoreAgentHookFile returned false")
	}
	restored, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, restored, []byte(`{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"/usr/local/bin/sir guard evaluate --agent claude"}]}]}}`)) {
		t.Fatalf("managed policy restore did not reinstate the manifest subtree:\n%s", restored)
	}
}

func TestDetectChangedGlobalHooksStrictErrorsForUnmanagedInstalledHookFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	codexDir := filepath.Join(tmpHome, ".codex")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}

	l := lease.DefaultLease()
	leaseHash, err := session.HashManagedLease(l)
	if err != nil {
		t.Fatal(err)
	}
	managedHooks := json.RawMessage(`{"PreToolUse":[{"matcher":".*","hooks":[{"type":"command","command":"/usr/local/bin/sir guard evaluate --agent claude"}]}]}`)
	hookHash, err := session.HashManagedHooksSubtree(managedHooks)
	if err != nil {
		t.Fatal(err)
	}
	manifest := map[string]interface{}{
		"managed":            true,
		"policy_version":     "2026-04-09",
		"managed_lease":      l,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": managedHooks,
		},
		"managed_hook_hashes": map[string]string{
			"claude": hookHash,
		},
	}
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(tmpHome, "managed-policy.json")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(session.ManagedPolicyPathEnvVar, manifestPath)

	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"hooks":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{"PreToolUse":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := DetectChangedGlobalHooksStrict(); err == nil {
		t.Fatal("expected DetectChangedGlobalHooksStrict to fail for unmanaged installed hook file")
	}
}
