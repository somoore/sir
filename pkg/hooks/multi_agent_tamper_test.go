package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// jsonEqual compares two JSON byte slices for semantic equality,
// ignoring whitespace and key ordering. AutoRestoreAgentHookFile now
// writes through json.MarshalIndent which canonicalizes formatting, so
// byte-for-byte comparison with a hand-written literal no longer
// matches even when the structure is identical.
func jsonEqual(t *testing.T, got, want []byte) bool {
	t.Helper()
	var gotV, wantV interface{}
	if err := json.Unmarshal(got, &gotV); err != nil {
		t.Errorf("jsonEqual: got is not valid JSON: %v\n  got: %s", err, got)
		return false
	}
	if err := json.Unmarshal(want, &wantV); err != nil {
		t.Errorf("jsonEqual: want is not valid JSON: %v\n  want: %s", err, want)
		return false
	}
	return reflect.DeepEqual(gotV, wantV)
}

// TestDetectChangedGlobalHooks_CodexTamperRestoresCodex verifies the real
// bug the external reviewer flagged: when ~/.codex/hooks.json drifts from
// its canonical backup, the restore path must target the Codex file — not
// hardcode ~/.claude/settings.json. Regression guard for the pre-fix
// behavior where post_evaluate.go and config_change.go always restored
// Claude regardless of which config actually changed.
func TestDetectChangedGlobalHooks_CodexTamperRestoresCodex(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	// Set up Claude: canonical == live (no tamper)
	claudeDir := filepath.Join(tmpHome, ".claude")
	sirDir := filepath.Join(tmpHome, ".sir")
	codexDir := filepath.Join(tmpHome, ".codex")
	for _, d := range []string{claudeDir, codexDir, sirDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	claudeContent := []byte(`{"hooks":{"PreToolUse":"claude-original"}}`)
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), claudeContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), claudeContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Codex: canonical has original; live file has been tampered.
	codexOriginal := []byte(`{"hooks":{"PreToolUse":"codex-original"}}`)
	codexTampered := []byte(`{"hooks":{"PreToolUse":"codex-TAMPERED"}}`)
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical-codex.json"), codexOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	codexLive := filepath.Join(codexDir, "hooks.json")
	if err := os.WriteFile(codexLive, codexTampered, 0o600); err != nil {
		t.Fatal(err)
	}

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 {
		t.Fatalf("expected 1 changed file (Codex), got %d: %+v", len(changed), changed)
	}
	if !strings.Contains(changed[0].DisplayPath, "codex") {
		t.Errorf("expected Codex file flagged, got %q", changed[0].DisplayPath)
	}
	if changed[0].AgentName != "Codex" {
		t.Errorf("expected AgentName=Codex, got %q", changed[0].AgentName)
	}

	// Restore should overwrite the tampered Codex file — NOT touch Claude.
	if !AutoRestoreAgentHookFile(changed[0]) {
		t.Fatal("AutoRestoreAgentHookFile returned false")
	}
	restored, err := os.ReadFile(codexLive)
	if err != nil {
		t.Fatalf("read restored codex file: %v", err)
	}
	if !jsonEqual(t, restored, codexOriginal) {
		t.Errorf("codex file not restored to canonical.\n got: %s\nwant: %s", restored, codexOriginal)
	}

	// Claude file must still be untouched.
	claudeLive, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(claudeLive) != string(claudeContent) {
		t.Errorf("Claude file was touched during Codex restore: %s", claudeLive)
	}

	// Sanity: after restore, no drift remains.
	stillChanged := DetectChangedGlobalHooks()
	if len(stillChanged) != 0 {
		t.Errorf("expected no drift after restore, got %+v", stillChanged)
	}
}

// TestDetectChangedGlobalHooks_BothChanged handles the rare case where an
// attacker (or a bad upgrade) modified both agents' configs at once.
// FormatChangedHookTargets must list both so the ledger target shows the
// full scope of the tamper.
func TestDetectChangedGlobalHooks_BothChanged(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	claudeDir := filepath.Join(tmpHome, ".claude")
	codexDir := filepath.Join(tmpHome, ".codex")
	for _, d := range []string{claudeDir, codexDir, sirDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), []byte(`{"v":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-codex.json"), []byte(`{"v":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"v":"tampered-claude"}`), 0o600)
	_ = os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{"v":"tampered-codex"}`), 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 2 {
		t.Fatalf("expected 2 changed files, got %d", len(changed))
	}
	target := FormatChangedHookTargets(changed)
	if !strings.Contains(target, ".claude/settings.json") || !strings.Contains(target, ".codex/hooks.json") {
		t.Errorf("target should list both files: %q", target)
	}
}

// TestDetectChangedGlobalHooks_GeminiTamperRestoresGemini mirrors the Codex
// regression test for the Gemini CLI hook file. When ~/.gemini/settings.json
// drifts from its canonical backup, the restore path must target the Gemini
// file specifically — not Claude or Codex.
func TestDetectChangedGlobalHooks_GeminiTamperRestoresGemini(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	claudeDir := filepath.Join(tmpHome, ".claude")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	sirDir := filepath.Join(tmpHome, ".sir")
	for _, d := range []string{claudeDir, geminiDir, sirDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	// Claude: canonical == live, no tamper.
	claudeContent := []byte(`{"hooks":{"PreToolUse":"claude-original"}}`)
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), claudeContent, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), claudeContent, 0o600); err != nil {
		t.Fatal(err)
	}

	// Gemini: canonical has original; live file has been tampered.
	geminiOriginal := []byte(`{"hooks":{"BeforeTool":"gemini-original"}}`)
	geminiTampered := []byte(`{"hooks":{"BeforeTool":"gemini-TAMPERED"}}`)
	if err := os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), geminiOriginal, 0o600); err != nil {
		t.Fatal(err)
	}
	geminiLive := filepath.Join(geminiDir, "settings.json")
	if err := os.WriteFile(geminiLive, geminiTampered, 0o600); err != nil {
		t.Fatal(err)
	}

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 {
		t.Fatalf("expected 1 changed file (Gemini), got %d: %+v", len(changed), changed)
	}
	if !strings.Contains(changed[0].DisplayPath, "gemini") {
		t.Errorf("expected Gemini file flagged, got %q", changed[0].DisplayPath)
	}
	if changed[0].AgentName != "Gemini CLI" {
		t.Errorf("expected AgentName=Gemini CLI, got %q", changed[0].AgentName)
	}

	if !AutoRestoreAgentHookFile(changed[0]) {
		t.Fatal("AutoRestoreAgentHookFile returned false")
	}
	restored, err := os.ReadFile(geminiLive)
	if err != nil {
		t.Fatalf("read restored gemini file: %v", err)
	}
	if !jsonEqual(t, restored, geminiOriginal) {
		t.Errorf("gemini file not restored to canonical.\n got: %s\nwant: %s", restored, geminiOriginal)
	}

	// Claude file must still be untouched.
	claudeLive, err := os.ReadFile(filepath.Join(claudeDir, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(claudeLive) != string(claudeContent) {
		t.Errorf("Claude file was touched during Gemini restore: %s", claudeLive)
	}

	stillChanged := DetectChangedGlobalHooks()
	if len(stillChanged) != 0 {
		t.Errorf("expected no drift after restore, got %+v", stillChanged)
	}
}

// TestDetectChangedGlobalHooks_AllThreeChanged extends the multi-agent
// tamper coverage to all three host agents at once. FormatChangedHookTargets
// must list every drifted file so the ledger target shows the full scope of
// the tamper.
func TestDetectChangedGlobalHooks_AllThreeChanged(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	claudeDir := filepath.Join(tmpHome, ".claude")
	codexDir := filepath.Join(tmpHome, ".codex")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	for _, d := range []string{claudeDir, codexDir, geminiDir, sirDir} {
		_ = os.MkdirAll(d, 0o755)
	}
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), []byte(`{"v":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-codex.json"), []byte(`{"v":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), []byte(`{"v":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), []byte(`{"v":"tampered-claude"}`), 0o600)
	_ = os.WriteFile(filepath.Join(codexDir, "hooks.json"), []byte(`{"v":"tampered-codex"}`), 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), []byte(`{"v":"tampered-gemini"}`), 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 3 {
		t.Fatalf("expected 3 changed files, got %d", len(changed))
	}
	target := FormatChangedHookTargets(changed)
	if !strings.Contains(target, ".claude/settings.json") ||
		!strings.Contains(target, ".codex/hooks.json") ||
		!strings.Contains(target, ".gemini/settings.json") {
		t.Errorf("target should list all three files: %q", target)
	}
}

// TestDetectChangedGlobalHooks_SkipsAgentsWithoutCanonical ensures agents
// that sir never installed for (no canonical backup) are NOT falsely
// flagged. A user with only Claude installed must not see Codex drift
// warnings.
func TestDetectChangedGlobalHooks_SkipsAgentsWithoutCanonical(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	claudeDir := filepath.Join(tmpHome, ".claude")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(claudeDir, 0o755)
	// Claude's live file is a realistic settings file with a hooks
	// subtree. The canonical is the new trimmed format: the subtree
	// itself, no outer wrapper.
	live := []byte(`{"hooks":{"PreToolUse":[{"command":"sir"}]}}`)
	canonical := []byte(`{"PreToolUse":[{"command":"sir"}]}`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical.json"), canonical, 0o600)
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"), live, 0o600)
	// No codex canonical, no codex file. DetectChangedGlobalHooks must not
	// report Codex as drifted.

	changed := DetectChangedGlobalHooks()
	if len(changed) != 0 {
		t.Errorf("expected no drift, got %+v", changed)
	}
}

// --- Subtree-scoped tamper detection -------------------------------------
//
// The following tests exercise the post-refactor behavior: tamper
// detection compares only the top-level "hooks" subtree, not the whole
// settings file. See plans/glittery-painting-moler.md for context.

// TestDetectChangedGlobalHooks_GeminiMcpAddDoesNotTrip verifies that a
// user adding a legitimate MCP server to ~/.gemini/settings.json does
// NOT trigger tamper detection. This is the Gemini friction case that
// motivated the refactor: `gemini mcp add`, theme changes, and auth
// switches all write to settings.json and would trip whole-file
// comparison.
func TestDetectChangedGlobalHooks_GeminiMcpAddDoesNotTrip(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	// Canonical: the hooks subtree only (new format).
	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]}`)
	// Live: same hooks subtree, plus legitimate non-hook fields the
	// user added or that gemini-cli wrote during normal operation.
	live := []byte(`{
  "hooks": {"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]},
  "mcpServers": {"evil-mcp": {"command": "node", "args": ["/x.js"]}},
  "theme": "Dracula",
  "selectedAuthType": "oauth-personal"
}`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), canonical, 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), live, 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 0 {
		t.Errorf("expected no drift from mcpServers/theme edits, got %+v", changed)
	}
}

// TestDetectChangedGlobalHooks_GeminiHooksEditStillTrips verifies the
// security property holds: an attacker who rewrites the hooks subtree
// to disable or redirect sir's hooks is still caught even though
// non-hook tampering no longer trips.
func TestDetectChangedGlobalHooks_GeminiHooksEditStillTrips(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]}`)
	// Attacker replaces sir's hook command with a no-op to bypass.
	live := []byte(`{
  "hooks": {"BeforeTool":[{"hooks":[{"command":"/bin/true"}]}]},
  "mcpServers": {"pencil": {}}
}`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), canonical, 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), live, 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 {
		t.Fatalf("expected Gemini flagged, got %d: %+v", len(changed), changed)
	}
	if changed[0].AgentName != "Gemini CLI" {
		t.Errorf("expected Gemini CLI, got %q", changed[0].AgentName)
	}
}

// TestAutoRestoreAgentHookFile_PreservesNonHookFields verifies that
// surgical restore replaces only the hooks subtree and leaves user
// mcpServers, theme, and other fields intact.
func TestAutoRestoreAgentHookFile_PreservesNonHookFields(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]}`)
	live := []byte(`{
  "hooks": {"BeforeTool":[{"hooks":[{"command":"/bin/true"}]}]},
  "mcpServers": {"pencil": {"command": "/pencil"}, "evil-mcp": {"command": "node"}},
  "theme": "Dracula",
  "selectedAuthType": "oauth-personal"
}`)
	canonPath := filepath.Join(sirDir, "hooks-canonical-gemini.json")
	livePath := filepath.Join(geminiDir, "settings.json")
	_ = os.WriteFile(canonPath, canonical, 0o600)
	_ = os.WriteFile(livePath, live, 0o600)

	f := AgentHookFile{
		DisplayPath:   "~/.gemini/settings.json",
		AbsPath:       livePath,
		CanonicalPath: canonPath,
		AgentName:     "Gemini CLI",
	}
	if !AutoRestoreAgentHookFile(f) {
		t.Fatal("AutoRestoreAgentHookFile returned false")
	}

	restored, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(restored, &got); err != nil {
		t.Fatalf("restored file is not valid JSON: %v\n%s", err, restored)
	}

	// Hooks subtree must now match the canonical.
	hooksSubtree, err := json.Marshal(got["hooks"])
	if err != nil {
		t.Fatalf("marshal hooks subtree: %v", err)
	}
	if !jsonEqual(t, hooksSubtree, canonical) {
		t.Errorf("hooks subtree not restored.\n got: %s\nwant: %s", hooksSubtree, canonical)
	}

	// Non-hook fields must be preserved.
	if got["theme"] != "Dracula" {
		t.Errorf("theme was lost: %v", got["theme"])
	}
	if got["selectedAuthType"] != "oauth-personal" {
		t.Errorf("selectedAuthType was lost: %v", got["selectedAuthType"])
	}
	mcp, ok := got["mcpServers"].(map[string]interface{})
	if !ok {
		t.Fatalf("mcpServers was lost: %v", got["mcpServers"])
	}
	if _, ok := mcp["pencil"]; !ok {
		t.Error("mcpServers.pencil was lost")
	}
	if _, ok := mcp["evil-mcp"]; !ok {
		t.Error("mcpServers.evil-mcp was lost")
	}

	// And drift is cleared.
	stillChanged := DetectChangedGlobalHooks()
	for _, c := range stillChanged {
		if c.AgentName == "Gemini CLI" {
			t.Errorf("Gemini still drifted after restore: %+v", c)
		}
	}
}

// TestDetectChangedGlobalHooks_CorruptedLiveFileStillTrips verifies the
// fail-closed fallback: if the live file is not valid JSON, tamper
// detection falls back to whole-file comparison and (since a corrupt
// file won't match the canonical) flags the agent.
func TestDetectChangedGlobalHooks_CorruptedLiveFileStillTrips(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir"}]}]}`)
	// Corrupt: trailing garbage, not valid JSON.
	live := []byte(`{"hooks":{"BeforeTool": broken`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), canonical, 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), live, 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 || changed[0].AgentName != "Gemini CLI" {
		t.Errorf("expected Gemini flagged on corrupt live file, got %+v", changed)
	}
}

// TestDetectChangedGlobalHooks_HooksKeyRemovedTrips verifies that an
// attacker who tries to bypass hooks by deleting the "hooks" key from
// the settings file is still caught — the extracted subtree is "null"
// on the live side but the canonical has real hooks, so they compare
// unequal.
func TestDetectChangedGlobalHooks_HooksKeyRemovedTrips(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir"}]}]}`)
	// No hooks key at all — attacker tried to disable sir by deletion.
	live := []byte(`{"theme": "Dracula", "mcpServers": {}}`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), canonical, 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), live, 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 || changed[0].AgentName != "Gemini CLI" {
		t.Errorf("expected Gemini flagged when hooks key is removed, got %+v", changed)
	}
}

// TestHashGlobalHooksFile_ScopedToHooksSubtree verifies that
// hashGlobalHooksFile (the session-start whole-hash used in
// post_evaluate.go:278 and config_change.go:91) only hashes the hooks
// subtree, so legitimate non-hook edits between session start and a
// tool call do not trigger the session-fatal deny-all path.
func TestHashGlobalHooksFile_ScopedToHooksSubtree(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	claudeDir := filepath.Join(tmpHome, ".claude")
	codexDir := filepath.Join(tmpHome, ".codex")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	for _, d := range []string{claudeDir, codexDir, geminiDir} {
		_ = os.MkdirAll(d, 0o755)
	}

	// Session-start snapshot.
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"command":"sir"}]},"permissions":{"allow":["*"]}}`), 0o600)
	_ = os.WriteFile(filepath.Join(codexDir, "hooks.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"command":"sir"}]}}`), 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"),
		[]byte(`{"hooks":{"BeforeTool":[{"command":"sir"}]},"mcpServers":{},"theme":"GitHub"}`), 0o600)

	before, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile at session start: %v", err)
	}

	// User edits ONLY non-hook fields across all three agents.
	_ = os.WriteFile(filepath.Join(claudeDir, "settings.json"),
		[]byte(`{"hooks":{"PreToolUse":[{"command":"sir"}]},"permissions":{"allow":["*"]},"env":{"FOO":"bar"}}`), 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"),
		[]byte(`{"hooks":{"BeforeTool":[{"command":"sir"}]},"mcpServers":{"evil-mcp":{"command":"node"}},"theme":"Dracula","selectedAuthType":"oauth-personal"}`), 0o600)

	after, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile after non-hook edits: %v", err)
	}

	if before != after {
		t.Errorf("hash changed on non-hook edits — scoping is wrong.\n before: %s\n  after: %s", before, after)
	}

	// Now edit the hooks subtree itself. Hash must change.
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"),
		[]byte(`{"hooks":{"BeforeTool":[{"command":"/bin/true"}]},"mcpServers":{"evil-mcp":{"command":"node"}},"theme":"Dracula"}`), 0o600)

	tampered, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile after hook edit: %v", err)
	}
	if tampered == after {
		t.Errorf("hash did not change on hooks subtree edit — detector broken")
	}
}

func TestHashGlobalHooksFile_ManagedPolicyStillReadsLiveCurrentState(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	policyPath := filepath.Join(tmpHome, "managed-policy.json")
	t.Setenv(session.ManagedPolicyPathEnvVar, policyPath)

	claudeDir := filepath.Join(tmpHome, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatalf("mkdir claude: %v", err)
	}
	live := []byte(`{"hooks":{"PreToolUse":[{"command":"sir"}]},"permissions":{"allow":["*"]}}`)
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), live, 0o600); err != nil {
		t.Fatalf("write live settings: %v", err)
	}

	managedLease := lease.DefaultLease()
	leaseHash, err := session.HashManagedLease(managedLease)
	if err != nil {
		t.Fatalf("HashManagedLease: %v", err)
	}
	managedHooks := json.RawMessage(`{"PreToolUse":[{"command":"sir"}]}`)
	hookHash, err := session.HashManagedHooksSubtree(managedHooks)
	if err != nil {
		t.Fatalf("HashManagedHooksSubtree: %v", err)
	}
	doc := map[string]interface{}{
		"managed":            true,
		"policy_version":     "2026-04-09",
		"managed_lease":      managedLease,
		"managed_lease_hash": leaseHash,
		"managed_hooks": map[string]json.RawMessage{
			"claude": managedHooks,
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
		t.Fatalf("write policy: %v", err)
	}

	baselineHash, ok, err := managedGlobalHooksHash()
	if err != nil {
		t.Fatalf("managedGlobalHooksHash: %v", err)
	}
	if !ok {
		t.Fatal("expected managedGlobalHooksHash to be active")
	}
	liveHash, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile: %v", err)
	}
	if liveHash != baselineHash {
		t.Fatalf("expected matching live/baseline hashes before tamper: live=%s baseline=%s", liveHash, baselineHash)
	}

	tampered := []byte(`{"hooks":{"PreToolUse":[{"command":"/bin/true"}]},"permissions":{"allow":["*"]}}`)
	if err := os.WriteFile(filepath.Join(claudeDir, "settings.json"), tampered, 0o600); err != nil {
		t.Fatalf("write tampered settings: %v", err)
	}

	afterHash, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile after tamper: %v", err)
	}
	if afterHash == baselineHash {
		t.Fatal("live hook hash did not change under managed policy")
	}
	changed := DetectChangedGlobalHooks()
	if len(changed) != 1 || changed[0].AgentName != "Claude Code" {
		t.Fatalf("expected Claude drift under managed policy, got %+v", changed)
	}
}

// TestDetectChangedGlobalHooks_LegacyWholeFileCanonical verifies that
// users upgrading from a pre-refactor sir install — whose canonical is
// a full settings wrapper, not just the hooks subtree — do NOT see a
// spurious tamper alert on first run. The canonical extraction path
// recognizes the legacy wrapper by the presence of a top-level "hooks"
// key and pulls the subtree before comparing.
func TestDetectChangedGlobalHooks_LegacyWholeFileCanonical(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	sirDir := filepath.Join(tmpHome, ".sir")
	geminiDir := filepath.Join(tmpHome, ".gemini")
	_ = os.MkdirAll(sirDir, 0o755)
	_ = os.MkdirAll(geminiDir, 0o755)

	// Legacy canonical: whole settings file including mcpServers as
	// frozen at install time. Simulates a sir install from before this
	// refactor.
	legacyCanonical := []byte(`{
  "hooks": {"BeforeTool":[{"command":"sir"}]},
  "mcpServers": {"pencil": {}},
  "theme": "GitHub"
}`)
	// Live: same hooks, but user has since added a new MCP server and
	// changed the theme. Under whole-file compare this would trip;
	// under subtree compare it must not.
	live := []byte(`{
  "hooks": {"BeforeTool":[{"command":"sir"}]},
  "mcpServers": {"pencil": {}, "new-mcp": {"command": "node"}},
  "theme": "Dracula"
}`)
	_ = os.WriteFile(filepath.Join(sirDir, "hooks-canonical-gemini.json"), legacyCanonical, 0o600)
	_ = os.WriteFile(filepath.Join(geminiDir, "settings.json"), live, 0o600)

	changed := DetectChangedGlobalHooks()
	if len(changed) != 0 {
		t.Errorf("legacy whole-file canonical should compare via hooks subtree; got drift: %+v", changed)
	}
}
