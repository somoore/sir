package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// TestCmdInstall_ConfigJSONIsAPostureFile verifies that `sir install`
// appends ~/.sir/config.json to the lease's PostureFiles so subsequent
// agent-initiated Write/Edit calls against it route through the
// posture-file ask gate. A compromised agent must not silently flip
// mcp_trust_posture from strict to permissive.
func TestCmdInstall_ConfigJSONIsAPostureFile(t *testing.T) {
	env := newTestEnv(t)

	mcpConfig := `{"mcpServers": {"x": {"command": "y"}}}`
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
	expected := filepath.Join(env.home, ".sir", "config.json")
	found := false
	for _, p := range l.PostureFiles {
		if p == expected {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q in PostureFiles, got %v", expected, l.PostureFiles)
	}
}
