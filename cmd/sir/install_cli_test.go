package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// -------------------------------------------------------------------
// cmdInstall tests (non-interactive, using --yes flag internally)
// -------------------------------------------------------------------

func TestCmdInstall_CreatesStateDir(t *testing.T) {
	env := newTestEnv(t)

	// Remove state dir so install creates it
	os.RemoveAll(env.stateDir)

	// Create posture files so SessionStart succeeds
	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	// Simulate --yes flag by injecting it into os.Args
	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	// Verify state dir was created
	if _, err := os.Stat(env.stateDir); os.IsNotExist(err) {
		t.Error("expected state directory to be created")
	}
}

func TestCmdInstall_WritesLease(t *testing.T) {
	env := newTestEnv(t)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	// Verify lease was written
	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatalf("expected lease to be created: %v", err)
	}
	if l.Mode != "guard" {
		t.Errorf("expected mode 'guard', got %q", l.Mode)
	}
	if l.LeaseID != "default" {
		t.Errorf("expected lease ID 'default', got %q", l.LeaseID)
	}
}

func TestCmdInstall_ObserveMode(t *testing.T) {
	env := newTestEnv(t)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "observe", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "observe")

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	if !l.ObserveOnly {
		t.Error("expected ObserveOnly to be true in observe mode")
	}
}

func TestCmdInstall_WritesHooksToGlobalSettings(t *testing.T) {
	env := newTestEnv(t)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	config := env.readSettingsJSON()
	hooks, ok := config["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("expected hooks key in settings.json")
	}

	// Verify PreToolUse and PostToolUse arrays contain sir entries
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		arr, ok := hooks[event].([]interface{})
		if !ok || len(arr) == 0 {
			t.Errorf("expected non-empty %s array", event)
			continue
		}
		found := false
		for _, entry := range arr {
			em, _ := entry.(map[string]interface{})
			if innerHooks, ok := em["hooks"].([]interface{}); ok {
				for _, ih := range innerHooks {
					ihm, _ := ih.(map[string]interface{})
					if cmd, _ := ihm["command"].(string); cmd != "" {
						if cmd == "sir guard evaluate" || cmd == "sir guard post-evaluate" {
							found = true
						}
					}
				}
			}
		}
		if !found {
			t.Errorf("expected sir guard hook in %s", event)
		}
	}
}

func TestCmdInstall_MergesWithExistingSettings(t *testing.T) {
	env := newTestEnv(t)

	// Pre-existing settings with custom key
	env.writeSettingsJSON(map[string]interface{}{
		"customKey": "customValue",
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": "other-tool check",
				},
			},
		},
	})

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	config := env.readSettingsJSON()

	// Custom key preserved
	if config["customKey"] != "customValue" {
		t.Error("expected customKey to be preserved during merge")
	}

	// Other hooks preserved
	hooks := config["hooks"].(map[string]interface{})
	preArr := hooks["PreToolUse"].([]interface{})

	// Should have sir hook + existing hook
	if len(preArr) < 2 {
		t.Errorf("expected at least 2 PreToolUse entries (sir + existing), got %d", len(preArr))
	}
}

func TestCmdInstall_DiscoversMCPServers(t *testing.T) {
	env := newTestEnv(t)

	// Create .mcp.json with servers
	mcpConfig := `{"mcpServers": {"test-mcp": {"command": "test-bin"}}}`
	os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	l, err := lease.Load(env.leasePath)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range l.ApprovedMCPServers {
		if s == "test-mcp" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'test-mcp' in ApprovedMCPServers, got %v", l.ApprovedMCPServers)
	}
}

func TestCmdInstall_RewritesRawMCPServersThroughProxy(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"project-raw":{"command":"node","args":["server.js"],"env":{"MODE":"dev"}}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"theme": "dark",
		"mcpServers": map[string]interface{}{
			"global-raw": map[string]interface{}{
				"command": "python3",
				"args":    []string{"global.py"},
			},
		},
	})
	geminiPath := filepath.Join(env.home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiPath, []byte(`{"theme":"dracula","mcpServers":{"gemini-raw":{"command":"ruby","args":["gemini.rb"]}}}`), 0o644); err != nil {
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

	projectDoc, err := readJSONFileMap(filepath.Join(env.projectRoot, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	projectServers := projectDoc["mcpServers"].(map[string]interface{})
	projectEntry := projectServers["project-raw"].(map[string]interface{})
	if projectEntry["command"] != "sir" {
		t.Fatalf("expected project MCP command to be rewritten to sir, got %#v", projectEntry["command"])
	}
	projectArgs, ok := interfaceSliceToStrings(projectEntry["args"])
	if !ok || len(projectArgs) < 3 || projectArgs[0] != "mcp-proxy" || projectArgs[1] != "node" {
		t.Fatalf("expected project MCP args to wrap original command, got %#v", projectEntry["args"])
	}
	if envMap := projectEntry["env"].(map[string]interface{}); envMap["MODE"] != "dev" {
		t.Fatalf("expected project MCP env to be preserved, got %#v", projectEntry["env"])
	}

	globalDoc := env.readSettingsJSON()
	globalServers := globalDoc["mcpServers"].(map[string]interface{})
	globalEntry := globalServers["global-raw"].(map[string]interface{})
	if globalEntry["command"] != "sir" {
		t.Fatalf("expected global MCP command to be rewritten to sir, got %#v", globalEntry["command"])
	}
	globalArgs, ok := interfaceSliceToStrings(globalEntry["args"])
	if !ok || len(globalArgs) < 3 || globalArgs[0] != "mcp-proxy" || globalArgs[1] != "python3" {
		t.Fatalf("expected global MCP args to wrap original command, got %#v", globalEntry["args"])
	}
	if globalDoc["theme"] != "dark" {
		t.Fatalf("expected global settings theme to survive rewrite, got %#v", globalDoc["theme"])
	}

	geminiDoc, err := readJSONFileMap(geminiPath)
	if err != nil {
		t.Fatal(err)
	}
	geminiServers := geminiDoc["mcpServers"].(map[string]interface{})
	geminiEntry := geminiServers["gemini-raw"].(map[string]interface{})
	if geminiEntry["command"] != "sir" {
		t.Fatalf("expected Gemini MCP command to be rewritten to sir, got %#v", geminiEntry["command"])
	}
	geminiArgs, ok := interfaceSliceToStrings(geminiEntry["args"])
	if !ok || len(geminiArgs) < 3 || geminiArgs[0] != "mcp-proxy" || geminiArgs[1] != "ruby" {
		t.Fatalf("expected Gemini MCP args to wrap original command, got %#v", geminiEntry["args"])
	}
	if geminiDoc["theme"] != "dracula" {
		t.Fatalf("expected Gemini settings theme to survive rewrite, got %#v", geminiDoc["theme"])
	}
}

func TestCmdInstall_ExplicitAgentDoesNotRewriteOtherMCPSurfaces(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"project-raw":{"command":"node","args":["server.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"claude-raw": map[string]interface{}{
				"command": "python3",
				"args":    []string{"global.py"},
			},
		},
	})

	codexDir := filepath.Join(env.home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes", "--agent", "codex"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	projectDoc, err := readJSONFileMap(filepath.Join(env.projectRoot, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	projectEntry := projectDoc["mcpServers"].(map[string]interface{})["project-raw"].(map[string]interface{})
	if projectEntry["command"] != "node" {
		t.Fatalf("expected explicit codex install to leave project MCP alone, got %#v", projectEntry["command"])
	}

	claudeDoc := env.readSettingsJSON()
	claudeEntry := claudeDoc["mcpServers"].(map[string]interface{})["claude-raw"].(map[string]interface{})
	if claudeEntry["command"] != "python3" {
		t.Fatalf("expected explicit codex install to leave Claude MCP alone, got %#v", claudeEntry["command"])
	}
}

func TestCmdInstall_SavesCanonicalHooksCopy(t *testing.T) {
	env := newTestEnv(t)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	canonicalPath := filepath.Join(env.home, ".sir", "hooks-canonical.json")
	if _, err := os.Stat(canonicalPath); os.IsNotExist(err) {
		t.Error("expected canonical hooks copy to be saved at ~/.sir/hooks-canonical.json")
	}
}

func TestCmdInstall_ReinstallDeduplicates(t *testing.T) {
	env := newTestEnv(t)

	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	// Install twice
	cmdInstall(env.projectRoot, "guard")
	cmdInstall(env.projectRoot, "guard")

	config := env.readSettingsJSON()
	hooks := config["hooks"].(map[string]interface{})
	preArr := hooks["PreToolUse"].([]interface{})

	// Count sir hooks — should be exactly 1 matcher group with sir.
	sirCount := 0
	for _, entry := range preArr {
		em, _ := entry.(map[string]interface{})
		if innerHooks, ok := em["hooks"].([]interface{}); ok {
			for _, ih := range innerHooks {
				ihm, _ := ih.(map[string]interface{})
				if cmd, _ := ihm["command"].(string); cmd == "sir guard evaluate" {
					sirCount++
				}
			}
		}
	}
	if sirCount != 1 {
		t.Errorf("expected exactly 1 sir guard evaluate hook after reinstall, got %d", sirCount)
	}
}

func TestCmdInstall_DefaultDetectsGeminiOnly(t *testing.T) {
	env := newTestEnv(t)

	if err := os.RemoveAll(filepath.Join(env.home, ".claude")); err != nil {
		t.Fatal(err)
	}
	geminiPath := filepath.Join(env.home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProjectInstallFixtures(t, env.projectRoot, "GEMINI.md", ".mcp.json")

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	geminiDoc, err := readJSONFileMap(geminiPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, ok := geminiDoc["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected hooks key in Gemini settings, got %#v", geminiDoc)
	}
	if _, ok := hooks["BeforeTool"]; !ok {
		t.Fatalf("expected Gemini hooks to contain BeforeTool, got %#v", hooks)
	}
	if _, err := os.Stat(filepath.Join(env.home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("expected Claude settings to stay absent, got err=%v", err)
	}
}

func TestCmdInstall_DefaultDetectsCodexOnlyAndEnablesFeatureFlag(t *testing.T) {
	env := newTestEnv(t)

	if err := os.RemoveAll(filepath.Join(env.home, ".claude")); err != nil {
		t.Fatal(err)
	}
	codexDir := filepath.Join(env.home, ".codex")
	if err := os.MkdirAll(codexDir, 0o755); err != nil {
		t.Fatal(err)
	}
	hooksPath := filepath.Join(codexDir, "hooks.json")
	if err := os.WriteFile(hooksPath, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProjectInstallFixtures(t, env.projectRoot, "AGENTS.md", ".mcp.json")

	origArgs := os.Args
	os.Args = []string{"sir", "install", "--yes"}
	defer func() { os.Args = origArgs }()

	cmdInstall(env.projectRoot, "guard")

	codexDoc, err := readJSONFileMap(hooksPath)
	if err != nil {
		t.Fatal(err)
	}
	hooks, ok := codexDoc["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected hooks key in Codex hooks.json, got %#v", codexDoc)
	}
	if _, ok := hooks["PreToolUse"]; !ok {
		t.Fatalf("expected Codex hooks to contain PreToolUse, got %#v", hooks)
	}
	configToml, err := os.ReadFile(filepath.Join(codexDir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(configToml) == "" || !strings.Contains(string(configToml), "codex_hooks = true") {
		t.Fatalf("expected Codex config.toml to enable codex_hooks, got %q", string(configToml))
	}
	if _, err := os.Stat(filepath.Join(env.home, ".claude", "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("expected Claude settings to stay absent, got err=%v", err)
	}
}

func writeProjectInstallFixtures(t *testing.T, projectRoot string, relPaths ...string) {
	t.Helper()
	for _, rel := range relPaths {
		path := filepath.Join(projectRoot, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
}

// -------------------------------------------------------------------
// loadLeaseForDoctor tests
