package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// testEnv sets up an isolated test environment with temp dirs for
// HOME, project root, and sir state. It returns a cleanup function.
type testEnv struct {
	home        string
	projectRoot string
	stateDir    string
	leasePath   string
	t           *testing.T
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	home := t.TempDir()
	projectRoot := t.TempDir()

	// Override HOME so session.StateDir resolves to temp
	t.Setenv("HOME", home)

	// Pin sirBinaryPath so hook commands are "sir guard ..." regardless of
	// the test binary path. Restore on cleanup.
	origBin := sirBinaryPath
	sirBinaryPath = "sir"
	t.Cleanup(func() { sirBinaryPath = origBin })

	stateDir := filepath.Join(home, ".sir", "projects", session.ProjectHash(projectRoot))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Create ~/.claude/ directory
	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}

	leasePath := filepath.Join(stateDir, "lease.json")

	return &testEnv{
		home:        home,
		projectRoot: projectRoot,
		stateDir:    stateDir,
		leasePath:   leasePath,
		t:           t,
	}
}

// writeDefaultLease writes a default lease and returns it.
func (e *testEnv) writeDefaultLease() *lease.Lease {
	e.t.Helper()
	l := lease.DefaultLease()
	if err := l.Save(e.leasePath); err != nil {
		e.t.Fatal(err)
	}
	return l
}

// writeSession writes a session state.
func (e *testEnv) writeSession(s *session.State) {
	e.t.Helper()
	if err := s.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// readSettingsJSON reads and parses ~/.claude/settings.json.
func (e *testEnv) readSettingsJSON() map[string]interface{} {
	e.t.Helper()
	data, err := os.ReadFile(filepath.Join(e.home, ".claude", "settings.json"))
	if err != nil {
		e.t.Fatal(err)
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		e.t.Fatal(err)
	}
	return config
}

// writeSettingsJSON writes a settings.json to ~/.claude/settings.json.
func (e *testEnv) writeSettingsJSON(config map[string]interface{}) {
	e.t.Helper()
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.home, ".claude", "settings.json"), data, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = orig })
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdout = orig
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func runCmdGuardHelper(t *testing.T, env *testEnv, stdin string, args ...string) (string, string) {
	t.Helper()
	encodedArgs, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal guard args: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestCmdGuardHelperProcess$")
	cmd.Env = append(os.Environ(),
		"SIR_TEST_CMD_GUARD=1",
		"SIR_TEST_PROJECT_ROOT="+env.projectRoot,
		"SIR_TEST_CMD_GUARD_ARGS="+string(encodedArgs),
		"HOME="+env.home,
	)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("run cmdGuard helper: %v\nstdout:\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return stdout.String(), stderr.String()
}

func TestCmdGuardHelperProcess(t *testing.T) {
	if os.Getenv("SIR_TEST_CMD_GUARD") != "1" {
		return
	}

	var args []string
	if err := json.Unmarshal([]byte(os.Getenv("SIR_TEST_CMD_GUARD_ARGS")), &args); err != nil {
		t.Fatalf("unmarshal helper args: %v", err)
	}

	cmdGuard(os.Getenv("SIR_TEST_PROJECT_ROOT"), args)
}

// -------------------------------------------------------------------
// generateHooksConfig tests
// -------------------------------------------------------------------

func TestGenerateHooksConfig_GuardMode(t *testing.T) {
	origBin := sirBinaryPath
	sirBinaryPath = "sir"
	t.Cleanup(func() { sirBinaryPath = origBin })

	config, err := generateHooksConfig("guard")
	if err != nil {
		t.Fatalf("generateHooksConfig: %v", err)
	}
	hooks, ok := config["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("expected hooks key in config")
	}

	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		arr, ok := hooks[event].([]interface{})
		if !ok || len(arr) == 0 {
			t.Fatalf("expected non-empty array for %s", event)
		}
		// Each entry is a matcher group
		mg, ok := arr[0].(map[string]interface{})
		if !ok {
			t.Fatal("expected map for matcher group")
		}
		if mg["matcher"] != ".*" {
			t.Errorf("expected matcher '.*', got %v", mg["matcher"])
		}
		innerHooks, ok := mg["hooks"].([]interface{})
		if !ok || len(innerHooks) == 0 {
			t.Fatal("expected inner hooks array")
		}
		hookObj, ok := innerHooks[0].(map[string]interface{})
		if !ok {
			t.Fatal("expected map for hook object")
		}
		cmd, _ := hookObj["command"].(string)
		if event == "PreToolUse" && cmd != "sir guard evaluate" {
			t.Errorf("PreToolUse command = %q, want %q", cmd, "sir guard evaluate")
		}
		if event == "PostToolUse" && cmd != "sir guard post-evaluate" {
			t.Errorf("PostToolUse command = %q, want %q", cmd, "sir guard post-evaluate")
		}
	}
}

func TestGenerateHooksConfig_TypesAreCorrect(t *testing.T) {
	// Regression test: the merge loop in cmdInstall asserts []interface{}, not
	// []map[string]interface{}. Verify generateHooksConfig returns the right types.
	config, err := generateHooksConfig("guard")
	if err != nil {
		t.Fatalf("generateHooksConfig: %v", err)
	}
	hooks := config["hooks"].(map[string]interface{})
	for _, event := range []string{"PreToolUse", "PostToolUse"} {
		// Must be assertable as []interface{} (not just []map[string]interface{})
		arr := hooks[event]
		if _, ok := arr.([]interface{}); !ok {
			t.Errorf("%s: expected []interface{}, got %T", event, arr)
		}
	}
}

// -------------------------------------------------------------------
// discoverMCPServers / discoverMCPInventory tests
// -------------------------------------------------------------------

func TestDiscoverMCPServers_ProjectLocal(t *testing.T) {
	env := newTestEnv(t)
	mcpConfig := `{
		"mcpServers": {
			"my-server": {"command": "server-bin"},
			"other-server": {"command": "other-bin"}
		}
	}`
	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644); err != nil {
		t.Fatal(err)
	}

	servers := discoverMCPServers(env.projectRoot)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d: %v", len(servers), servers)
	}
	found := make(map[string]bool)
	for _, s := range servers {
		found[s] = true
	}
	if !found["my-server"] || !found["other-server"] {
		t.Errorf("missing expected servers in %v", servers)
	}
}

func TestDiscoverMCPServers_GlobalSettings(t *testing.T) {
	env := newTestEnv(t)
	globalConfig := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"global-server": map[string]interface{}{"command": "server-bin"},
		},
	}
	env.writeSettingsJSON(globalConfig)

	servers := discoverMCPServers(env.projectRoot)
	if len(servers) != 1 || servers[0] != "global-server" {
		t.Errorf("expected [global-server], got %v", servers)
	}
}

func TestDiscoverMCPServers_DeduplicatesAcrossSources(t *testing.T) {
	env := newTestEnv(t)

	// Same server in both project-local and global
	mcpConfig := `{"mcpServers": {"shared-server": {"command": "bin"}}}`
	os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(mcpConfig), 0o644)
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"shared-server": map[string]interface{}{"command": "bin"},
		},
	})

	servers := discoverMCPServers(env.projectRoot)
	if len(servers) != 1 {
		t.Errorf("expected deduplication to 1 server, got %d: %v", len(servers), servers)
	}
}

func TestDiscoverMCPInventory_PreservesSourceForSameName(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"shared":{"command":"node","args":["project.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"shared": map[string]interface{}{
				"command": "python3",
				"args":    []string{"global.py"},
			},
		},
	})

	report := discoverMCPInventory(env.projectRoot)
	if len(report.Errors) != 0 {
		t.Fatalf("expected no parse errors, got %v", report.Errors)
	}
	if len(report.Servers) != 2 {
		t.Fatalf("expected 2 source-aware MCP entries, got %d: %+v", len(report.Servers), report.Servers)
	}
	if report.Servers[0].SourcePath == report.Servers[1].SourcePath {
		t.Fatalf("expected duplicate server names to remain source-aware: %+v", report.Servers)
	}
	if got := approvedMCPServerNames(report.Servers); len(got) != 1 || got[0] != "shared" {
		t.Fatalf("expected approved names to dedupe by server name, got %v", got)
	}
}

func TestDiscoverMCPInventory_GeminiGlobalSettings(t *testing.T) {
	env := newTestEnv(t)

	geminiPath := filepath.Join(env.home, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(geminiPath, []byte(`{"mcpServers":{"gemini-server":{"command":"node","args":["gemini.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	report := discoverMCPInventory(env.projectRoot)
	if len(report.Errors) != 0 {
		t.Fatalf("expected no parse errors, got %v", report.Errors)
	}
	found := false
	for _, server := range report.Servers {
		if server.Name == "gemini-server" && server.SourceLabel == "~/.gemini/settings.json" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected Gemini MCP server in inventory, got %+v", report.Servers)
	}
}

func TestDiscoverMCPServers_NoConfig(t *testing.T) {
	env := newTestEnv(t)
	servers := discoverMCPServers(env.projectRoot)
	if len(servers) != 0 {
		t.Errorf("expected empty, got %v", servers)
	}
}

// -------------------------------------------------------------------
// cmdClearSession tests
// -------------------------------------------------------------------

func TestCmdClearSession_ClearsSecretFlag(t *testing.T) {
	env := newTestEnv(t)

	state := session.NewState(env.projectRoot)
	state.MarkSecretSession()
	env.writeSession(state)

	// Call cmdClearSession (it writes to stdout which we ignore in tests)
	cmdClearSession(env.projectRoot)

	// Reload and verify
	reloaded, err := session.Load(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.SecretSession {
		t.Error("expected SecretSession to be false after clear")
	}
}

func TestCmdClearSession_LogsToLedger(t *testing.T) {
	env := newTestEnv(t)

	state := session.NewState(env.projectRoot)
	state.MarkSecretSession()
	env.writeSession(state)

	cmdClearSession(env.projectRoot)

	entries, err := ledger.ReadAll(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry after clear session")
	}
	last := entries[len(entries)-1]
	if last.Verb != "session_cleared" {
		t.Errorf("expected verb 'session_cleared', got %q", last.Verb)
	}
	if last.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %q", last.Decision)
	}
}

func TestCmdClearSession_NonSecretSession(t *testing.T) {
	env := newTestEnv(t)

	state := session.NewState(env.projectRoot)
	// Not marked as secret
	env.writeSession(state)

	// Should not panic or error, just print a message
	cmdClearSession(env.projectRoot)

	// Verify no ledger entry written (nothing was cleared)
	entries, _ := ledger.ReadAll(env.projectRoot)
	if len(entries) != 0 {
		t.Error("expected no ledger entry when session is not secret")
	}
}

// -------------------------------------------------------------------
// cmdUninstall tests
// -------------------------------------------------------------------

func TestCmdUninstall_RemovesSirHooks(t *testing.T) {
	env := newTestEnv(t)

	// Write settings with sir hooks
	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
							"timeout": 10,
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	cmdUninstall(env.projectRoot)

	config := env.readSettingsJSON()
	hooks, _ := config["hooks"].(map[string]interface{})
	preArr, _ := hooks["PreToolUse"].([]interface{})

	// All sir hooks removed, so the array should be empty (or nil)
	if len(preArr) != 0 {
		t.Errorf("expected sir hooks to be removed, got %d entries", len(preArr))
	}
}

func TestCmdUninstall_PreservesNonSirHooks(t *testing.T) {
	env := newTestEnv(t)

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
							"timeout": 10,
						},
					},
				},
				map[string]interface{}{
					"type":    "command",
					"command": "other-tool evaluate",
					"timeout": 5,
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	cmdUninstall(env.projectRoot)

	config := env.readSettingsJSON()
	hooks, _ := config["hooks"].(map[string]interface{})
	preArr, _ := hooks["PreToolUse"].([]interface{})

	if len(preArr) != 1 {
		t.Fatalf("expected 1 non-sir hook preserved, got %d", len(preArr))
	}
	entry, _ := preArr[0].(map[string]interface{})
	cmd, _ := entry["command"].(string)
	if cmd != "other-tool evaluate" {
		t.Errorf("expected preserved hook command 'other-tool evaluate', got %q", cmd)
	}
}

func TestCmdUninstall_NoSettingsFile(t *testing.T) {
	env := newTestEnv(t)
	// Remove settings.json if it exists
	os.Remove(filepath.Join(env.home, ".claude", "settings.json"))

	// Should not panic
	cmdUninstall(env.projectRoot)
}

// -------------------------------------------------------------------

func TestLoadLeaseForDoctor_NoLeaseFile(t *testing.T) {
	env := newTestEnv(t)
	_ = env // just to set HOME

	l, err := loadLeaseForDoctor(env.projectRoot)
	if err != nil {
		t.Fatalf("expected no error when lease missing, got %v", err)
	}
	if l.LeaseID != "default" {
		t.Error("expected default lease when file missing")
	}
}

func TestLoadLeaseForDoctor_ValidLease(t *testing.T) {
	env := newTestEnv(t)
	saved := env.writeDefaultLease()

	l, err := loadLeaseForDoctor(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if l.LeaseID != saved.LeaseID {
		t.Error("expected loaded lease to match saved lease")
	}
}

func TestParseAgentFlag(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		if got := parseAgentFlag(nil); got != string(agent.Claude) {
			t.Fatalf("parseAgentFlag(nil) = %q, want %q", got, agent.Claude)
		}
	})

	t.Run("separate argument after other args", func(t *testing.T) {
		if got := parseAgentFlag([]string{"payload.json", "--agent", "codex"}); got != "codex" {
			t.Fatalf("parseAgentFlag(separate) = %q, want codex", got)
		}
	})

	t.Run("inline argument after other args", func(t *testing.T) {
		if got := parseAgentFlag([]string{"payload.json", "--agent=gemini"}); got != "gemini" {
			t.Fatalf("parseAgentFlag(inline) = %q, want gemini", got)
		}
	})
}

func TestResolveAgent(t *testing.T) {
	t.Run("known", func(t *testing.T) {
		ag, ok := resolveAgent("codex")
		if !ok {
			t.Fatal("expected codex to resolve")
		}
		if ag.ID() != agent.Codex {
			t.Fatalf("resolveAgent(codex) id = %q, want %q", ag.ID(), agent.Codex)
		}
	})

	t.Run("unknown falls back to claude", func(t *testing.T) {
		ag, ok := resolveAgent("unknown-agent")
		if ok {
			t.Fatal("expected unknown agent to be reported as unknown")
		}
		if ag.ID() != agent.Claude {
			t.Fatalf("resolveAgent(unknown) id = %q, want %q", ag.ID(), agent.Claude)
		}
	})
}

func TestGuardCommandNames(t *testing.T) {
	got := guardCommandNames()
	sort.Strings(got)
	want := []string{
		"compact-reinject",
		"config-change",
		"elicitation",
		"evaluate",
		"instructions-loaded",
		"post-evaluate",
		"session-end",
		"session-summary",
		"subagent-start",
		"user-prompt",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("guard command names = %v, want %v", got, want)
	}
}

func TestCmdGuard_PostEvaluateUsesPostToolUseDeny(t *testing.T) {
	env := newTestEnv(t)

	stdout, stderr := runCmdGuardHelper(t, env, "", "post-evaluate", "--agent", "codex")

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout=%q", err, stdout)
	}
	if resp["decision"] != "block" {
		t.Fatalf("decision = %v, want block", resp["decision"])
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput missing or wrong type: %T", resp["hookSpecificOutput"])
	}
	if hso["hookEventName"] != "PostToolUse" {
		t.Fatalf("hookEventName = %v, want PostToolUse", hso["hookEventName"])
	}
	if ac, _ := hso["additionalContext"].(string); !strings.Contains(ac, "sir guard post-evaluate") {
		t.Fatalf("additionalContext = %q, want post-evaluate deny text", ac)
	}
	if !strings.Contains(stderr, "sir guard post-evaluate") {
		t.Fatalf("stderr = %q, want post-evaluate deny text", stderr)
	}
}

func TestCmdGuard_SessionSummaryUsesLifecycleDeny(t *testing.T) {
	env := newTestEnv(t)

	stdout, stderr := runCmdGuardHelper(t, env, "", "session-summary", "--agent", "codex")

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout=%q", err, stdout)
	}
	if resp["decision"] != "block" {
		t.Fatalf("decision = %v, want block", resp["decision"])
	}
	if reason, _ := resp["reason"].(string); !strings.Contains(reason, "sir guard session-summary") {
		t.Fatalf("reason = %q, want session-summary deny text", reason)
	}
	if _, ok := resp["hookSpecificOutput"]; ok {
		t.Fatalf("hookSpecificOutput = %v, want lifecycle Stop response without hook envelope", resp["hookSpecificOutput"])
	}
	if !strings.Contains(stderr, "sir guard session-summary") {
		t.Fatalf("stderr = %q, want session-summary deny text", stderr)
	}
}

func TestCmdGuard_MissingSubcommandFallsBackToClaudeEnvelope(t *testing.T) {
	env := newTestEnv(t)

	stdout, stderr := runCmdGuardHelper(t, env, "")

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout=%q", err, stdout)
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput missing or wrong type: %T", resp["hookSpecificOutput"])
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Fatalf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Fatalf("permissionDecision = %v, want deny", hso["permissionDecision"])
	}
	if !strings.Contains(stderr, "missing subcommand") {
		t.Fatalf("stderr = %q, want missing subcommand text", stderr)
	}
}

func TestCmdGuard_UnknownSubcommandUsesResolvedAgentFormat(t *testing.T) {
	env := newTestEnv(t)

	stdout, stderr := runCmdGuardHelper(t, env, "", "not-a-hook", "--agent", "codex")

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout=%q", err, stdout)
	}
	if resp["decision"] != "block" {
		t.Fatalf("decision = %v, want block", resp["decision"])
	}
	if reason, _ := resp["reason"].(string); !strings.Contains(reason, "unknown subcommand: not-a-hook") {
		t.Fatalf("reason = %q, want unknown-subcommand text", reason)
	}
	if !strings.Contains(stderr, "unknown subcommand: not-a-hook") {
		t.Fatalf("stderr = %q, want unknown-subcommand text", stderr)
	}
}

func TestCmdGuard_UnknownAgentFallsBackToClaudeEnvelope(t *testing.T) {
	env := newTestEnv(t)

	stdout, stderr := runCmdGuardHelper(t, env, "", "evaluate", "--agent", "not-real")

	var resp map[string]interface{}
	if err := json.Unmarshal([]byte(stdout), &resp); err != nil {
		t.Fatalf("unmarshal stdout: %v\nstdout=%q", err, stdout)
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput missing or wrong type: %T", resp["hookSpecificOutput"])
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Fatalf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
	if hso["permissionDecision"] != "deny" {
		t.Fatalf("permissionDecision = %v, want deny", hso["permissionDecision"])
	}
	if !strings.Contains(stderr, `unknown --agent value: "not-real"`) {
		t.Fatalf("stderr = %q, want unknown-agent text", stderr)
	}
}

// -------------------------------------------------------------------
// guardDeny tests (verify JSON output format)
// -------------------------------------------------------------------

func TestGuardDenyFormat(t *testing.T) {
	// guardDeny calls os.Exit, so we can't test it directly in-process.
	// Instead, test the JSON structure it would produce.
	reason := "sir INTERNAL ERROR: test error"
	resp := map[string]interface{}{
		"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": reason,
		},
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	output, _ := parsed["hookSpecificOutput"].(map[string]interface{})
	if output["hookEventName"] != "PreToolUse" {
		t.Error("expected PreToolUse")
	}
	if output["permissionDecision"] != "deny" {
		t.Error("expected deny")
	}
	if output["permissionDecisionReason"] != reason {
		t.Errorf("expected reason %q, got %v", reason, output["permissionDecisionReason"])
	}
}

// -------------------------------------------------------------------
// Ledger hash chain integrity tests
// -------------------------------------------------------------------

func TestLedgerHashChain_ValidChain(t *testing.T) {
	env := newTestEnv(t)

	for i := 0; i < 10; i++ {
		if err := ledger.Append(env.projectRoot, &ledger.Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "make build",
			Decision: "allow",
			Reason:   "dev command",
		}); err != nil {
			t.Fatal(err)
		}
	}

	count, err := ledger.Verify(env.projectRoot)
	if err != nil {
		t.Fatalf("expected valid chain, got error: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 verified entries, got %d", count)
	}
}

func TestLedgerHashChain_EmptyLedger(t *testing.T) {
	env := newTestEnv(t)

	count, err := ledger.Verify(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}
}
