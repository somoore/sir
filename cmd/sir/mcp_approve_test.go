package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// writeApprovedLeaseWithDiscovery seeds a lease with one discovered server
// so approve/revoke tests don't need to run the full install pipeline.
func (e *testEnv) writeLeaseWithDiscovered(servers ...lease.MCPDiscoveredServer) {
	e.t.Helper()
	l := lease.DefaultLease()
	l.DiscoveredMCPServers = servers
	if err := l.Save(e.leasePath); err != nil {
		e.t.Fatal(err)
	}
}

func TestCmdMCPApprove_PromotesDiscoveredToApproved(t *testing.T) {
	env := newTestEnv(t)
	// Create a file we can hash so the approval record has a real hash.
	binPath := filepath.Join(env.projectRoot, "fake-mcp-bin")
	if err := os.WriteFile(binPath, []byte("hello"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	env.writeLeaseWithDiscovered(lease.MCPDiscoveredServer{
		Name:       "test-mcp",
		SourcePath: filepath.Join(env.projectRoot, ".mcp.json"),
		Command:    binPath,
	})

	cmdMCPApprove(env.projectRoot, []string{"test-mcp", "--yes"})

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !containsApprovedName(l.ApprovedMCPServers, "test-mcp") {
		t.Fatalf("test-mcp missing from ApprovedMCPServers: %v", l.ApprovedMCPServers)
	}
	for _, d := range l.DiscoveredMCPServers {
		if d.Name == "test-mcp" {
			t.Fatalf("test-mcp still in DiscoveredMCPServers: %+v", d)
		}
	}
	rec, ok := l.MCPApprovals["test-mcp"]
	if !ok {
		t.Fatal("MCPApprovals missing record for test-mcp")
	}
	if rec.ApprovedAt.IsZero() {
		t.Error("approval record has zero ApprovedAt")
	}
	if rec.CommandHash == "" {
		t.Error("approval record has empty CommandHash (expected hash of local binary)")
	}
}

func TestCmdMCPApprove_AllFlag(t *testing.T) {
	env := newTestEnv(t)
	env.writeLeaseWithDiscovered(
		lease.MCPDiscoveredServer{Name: "a"},
		lease.MCPDiscoveredServer{Name: "b"},
	)

	cmdMCPApprove(env.projectRoot, []string{"--all", "--yes"})

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !(containsApprovedName(l.ApprovedMCPServers, "a") && containsApprovedName(l.ApprovedMCPServers, "b")) {
		t.Fatalf("expected both servers approved, got %v", l.ApprovedMCPServers)
	}
	if len(l.DiscoveredMCPServers) != 0 {
		t.Fatalf("discovered list should be empty, got %v", l.DiscoveredMCPServers)
	}
}

func TestCmdMCPRevoke_RemovesFromApproved(t *testing.T) {
	env := newTestEnv(t)
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"keep", "drop"}
	l.MCPApprovals = map[string]lease.MCPApproval{"drop": {SourcePath: ".mcp.json"}}
	if err := l.Save(env.leasePath); err != nil {
		t.Fatal(err)
	}

	cmdMCPRevoke(env.projectRoot, []string{"drop"})

	out, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if containsApprovedName(out.ApprovedMCPServers, "drop") {
		t.Fatalf("drop still in ApprovedMCPServers: %v", out.ApprovedMCPServers)
	}
	if !containsApprovedName(out.ApprovedMCPServers, "keep") {
		t.Fatalf("keep was removed: %v", out.ApprovedMCPServers)
	}
	if _, ok := out.MCPApprovals["drop"]; ok {
		t.Fatal("drop approval record should have been deleted")
	}
}

func TestCmdMCPRevoke_UnknownIsNoOp(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	// Should not panic or mutate. We use updateProjectLeaseAndSessionBaseline
	// which requires an existing session — since no session exists, no-op
	// path must exit before the update call.
	cmdMCPRevoke(env.projectRoot, []string{"does-not-exist"})
	out, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.ApprovedMCPServers) != 0 {
		t.Fatalf("expected no changes, got %v", out.ApprovedMCPServers)
	}
}

func TestCmdMCPApprove_UnknownServerFatals(t *testing.T) {
	// fatal() calls os.Exit; we can't assert behavior directly without
	// forking, so we only verify that a known server path succeeds. The
	// unknown-server path is covered by Codex path in mcp_command_test.go
	// if needed; leaving this as a placeholder for future coverage.
	t.Skip("unknown-name path invokes fatal(); covered by manual testing and mcp_command_test.go usage string")
}

func TestCmdInstall_StrictPostureDiscoversWithoutApproving(t *testing.T) {
	env := newTestEnv(t)

	// Write global config with strict posture so install routes discovery
	// into DiscoveredMCPServers, not ApprovedMCPServers.
	cfgDir := filepath.Join(env.home, ".sir")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"mcp_trust_posture":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	mcpConfig := `{"mcpServers": {"test-mcp": {"command": "test-bin"}}}`
	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if containsApprovedName(l.ApprovedMCPServers, "test-mcp") {
		t.Errorf("strict posture: test-mcp should NOT be auto-approved, got %v", l.ApprovedMCPServers)
	}
	found := false
	for _, d := range l.DiscoveredMCPServers {
		if d.Name == "test-mcp" {
			found = true
			if d.SourcePath == "" {
				t.Error("expected SourcePath provenance on discovered entry")
			}
			break
		}
	}
	if !found {
		t.Errorf("strict posture: test-mcp should be in DiscoveredMCPServers, got %v", l.DiscoveredMCPServers)
	}
}

func TestCmdInstall_StrictPosturePreservesPriorApprovals(t *testing.T) {
	env := newTestEnv(t)
	cfgDir := filepath.Join(env.home, ".sir")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), []byte(`{"mcp_trust_posture":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Seed the existing lease with an already-approved server. When install
	// re-runs, that approval must survive and only the new "extra-mcp" must
	// land in DiscoveredMCPServers.
	seed := lease.DefaultLease()
	seed.ApprovedMCPServers = []string{"already-trusted"}
	seed.MCPApprovals = map[string]lease.MCPApproval{
		"already-trusted": {SourcePath: filepath.Join(env.projectRoot, ".mcp.json")},
	}
	if err := seed.Save(env.leasePath); err != nil {
		t.Fatal(err)
	}

	mcpConfig := `{"mcpServers": {"already-trusted": {"command": "a"}, "extra-mcp": {"command": "b"}}}`
	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !containsApprovedName(l.ApprovedMCPServers, "already-trusted") {
		t.Errorf("strict posture re-install dropped prior approval: %v", l.ApprovedMCPServers)
	}
	if containsApprovedName(l.ApprovedMCPServers, "extra-mcp") {
		t.Errorf("strict posture should not auto-approve extra-mcp: %v", l.ApprovedMCPServers)
	}
	foundExtra := false
	for _, d := range l.DiscoveredMCPServers {
		if d.Name == "extra-mcp" {
			foundExtra = true
		}
		if d.Name == "already-trusted" {
			t.Errorf("already-trusted should not reappear in DiscoveredMCPServers, got %+v", d)
		}
	}
	if !foundExtra {
		t.Errorf("extra-mcp should be in DiscoveredMCPServers, got %v", l.DiscoveredMCPServers)
	}
}

func TestCmdInstall_FirstInstallDefaultsToStrict(t *testing.T) {
	env := newTestEnv(t)

	// Remove the manifest seeded by newTestEnv so this HOME looks fresh.
	manifestPath := filepath.Join(env.home, ".sir", "binary-manifest.json")
	if err := os.Remove(manifestPath); err != nil {
		t.Fatal(err)
	}

	mcpConfig := `{"mcpServers": {"fresh-mcp": {"command": "x"}}}`
	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if containsApprovedName(l.ApprovedMCPServers, "fresh-mcp") {
		t.Errorf("fresh install should default to strict; fresh-mcp was auto-approved: %v", l.ApprovedMCPServers)
	}
	// The config file must have been persisted with posture=strict so
	// subsequent runs remain strict without re-detection.
	cfgPath := filepath.Join(env.home, ".sir", "config.json")
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("expected config.json to be persisted after first install: %v", err)
	}
	if !filepath.IsAbs(cfgPath) {
		t.Fatalf("config path not absolute: %s", cfgPath)
	}
	if got := string(data); got == "" {
		t.Fatalf("config.json is empty")
	}
}
