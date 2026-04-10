package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func writeManagedPolicyForEnv(t *testing.T, env *testEnv, l *lease.Lease) string {
	t.Helper()
	claudeHooks := agent.NewClaudeAgent().GenerateHooksConfigMap(sirBinaryPath, l.Mode)
	rawHooks, err := json.Marshal(claudeHooks)
	if err != nil {
		t.Fatal(err)
	}
	subtree, err := hooks.ExtractManagedSubtree(rawHooks, "hooks")
	if err != nil {
		t.Fatal(err)
	}
	leaseHash, err := session.HashManagedLease(l)
	if err != nil {
		t.Fatal(err)
	}
	hookHash, err := session.HashManagedHooksSubtree(subtree)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]interface{}{
		"managed":            true,
		"policy_version":     "2026-04-09",
		"managed_lease":      l,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": subtree,
		},
		"managed_hook_hashes": map[string]string{
			"claude": hookHash,
		},
		"disabled_local_commands": []string{"allow-host", "allow-remote", "trust"},
	}
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env.home, "managed-policy.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(session.ManagedPolicyPathEnvVar, path)
	return path
}

func createDoctorPostureFiles(t *testing.T, env *testEnv) {
	t.Helper()
	for _, f := range []string{".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		path := filepath.Join(env.projectRoot, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnsureManagedCommandAllowed_DisablesLocalWidening(t *testing.T) {
	env := newTestEnv(t)
	path := writeManagedPolicyForEnv(t, env, lease.DefaultLease())
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}

	if err := ensureManagedCommandAllowed("allow-host"); err == nil {
		t.Fatal("expected allow-host to be blocked by managed policy")
	}
	if err := ensureManagedCommandAllowed("unlock"); err != nil {
		t.Fatalf("unlock should remain allowed: %v", err)
	}
}

func TestCmdInstall_ManagedModeUsesManifestLease(t *testing.T) {
	env := newTestEnv(t)
	createDoctorPostureFiles(t, env)

	managedLease := lease.DefaultLease()
	managedLease.Mode = "guard"
	managedLease.ApprovedHosts = []string{"localhost"}
	writeManagedPolicyForEnv(t, env, managedLease)

	origArgs := os.Args
	os.Args = []string{"sir", "install", "observe", "--yes", "--agent", "claude"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "observe")

	reloaded, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.ApprovedHosts) != 1 || reloaded.ApprovedHosts[0] != "localhost" {
		t.Fatalf("managed install did not apply manifest lease: %+v", reloaded.ApprovedHosts)
	}
	if reloaded.ObserveOnly {
		t.Fatal("managed install should not preserve local observe mode when policy is guard")
	}
}

func TestCmdInstall_ManagedModeDoesNotWidenApprovedMCPServers(t *testing.T) {
	env := newTestEnv(t)
	createDoctorPostureFiles(t, env)

	managedLease := lease.DefaultLease()
	writeManagedPolicyForEnv(t, env, managedLease)

	mcpConfig := []byte(`{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"]
    }
  }
}`)
	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), mcpConfig, 0o644); err != nil {
		t.Fatal(err)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "guard", "--yes", "--agent", "claude"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	reloaded, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded.ApprovedMCPServers) != len(managedLease.ApprovedMCPServers) {
		t.Fatalf("managed install widened approved_mcp_servers: got %+v want %+v", reloaded.ApprovedMCPServers, managedLease.ApprovedMCPServers)
	}
}

func TestCmdDoctor_ManagedModeRestoresLeaseAndHooks(t *testing.T) {
	env := newTestEnv(t)
	createDoctorPostureFiles(t, env)

	managedLease := lease.DefaultLease()
	managedLease.ApprovedHosts = []string{"localhost"}
	writeManagedPolicyForEnv(t, env, managedLease)

	claudeConfig := agent.NewClaudeAgent().GenerateHooksConfigMap(sirBinaryPath, managedLease.Mode)
	env.writeSettingsJSON(claudeConfig)
	if err := managedLease.Save(env.leasePath); err != nil {
		t.Fatal(err)
	}

	state := session.NewState(env.projectRoot)
	state.LeaseHash = mustManagedLeaseHash(t, managedLease)
	globalHash, err := posture.HashGlobalHooks(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	state.GlobalHookHash = globalHash
	env.writeSession(state)

	tamperedLease := lease.DefaultLease()
	tamperedLease.ApprovedHosts = append(tamperedLease.ApprovedHosts, "evil.example.com")
	if err := tamperedLease.Save(env.leasePath); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "evil guard evaluate",
						},
					},
				},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	if !strings.Contains(out, "Local baseline refresh is disabled under managed mode.") {
		t.Fatalf("doctor output missing managed-mode banner:\n%s", out)
	}
	if !strings.Contains(out, "Restored: lease.json from managed policy") {
		t.Fatalf("doctor output missing managed lease restore:\n%s", out)
	}
	if !strings.Contains(out, "hooks subtree from managed policy") {
		t.Fatalf("doctor output missing managed hook restore:\n%s", out)
	}

	reloaded, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if slicesContain(reloaded.ApprovedHosts, "evil.example.com") {
		t.Fatalf("managed doctor did not restore lease: %+v", reloaded.ApprovedHosts)
	}
	settingsRaw, err := os.ReadFile(filepath.Join(env.home, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(settingsRaw, []byte("evil guard evaluate")) {
		t.Fatalf("managed doctor did not restore claude hooks:\n%s", settingsRaw)
	}
}

func mustManagedLeaseHash(t *testing.T, l *lease.Lease) string {
	t.Helper()
	hash, err := session.HashManagedLease(l)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func slicesContain(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
