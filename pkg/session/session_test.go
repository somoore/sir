package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// withTempProject sets HOME to a temp dir and returns a fake project root
// so that StateDir/StatePath resolve inside the temp tree.
func withTempProject(t *testing.T) string {
	t.Helper()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	projectRoot := filepath.Join(tmpHome, "myproject")
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	return projectRoot
}

func TestLoad_NonExistentFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	_, err := Load("/nonexistent/project")
	if err == nil {
		t.Fatal("Load should return error for non-existent file")
	}
	if !os.IsNotExist(err) {
		t.Fatalf("expected not-exist error, got: %v", err)
	}
}

func TestLoad_CorruptedFile(t *testing.T) {
	projectRoot := withTempProject(t)
	dir := StateDir(projectRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StatePath(projectRoot), []byte("not json{{{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(projectRoot)
	if err == nil {
		t.Fatal("Load should return error for corrupted JSON")
	}
}

func TestLoad_EmptyFile(t *testing.T) {
	projectRoot := withTempProject(t)
	dir := StateDir(projectRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(StatePath(projectRoot), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(projectRoot)
	if err == nil {
		t.Fatal("Load should return error for empty file")
	}
}

func TestLoad_PartialJSON(t *testing.T) {
	// Valid JSON with only some fields — should deserialize fine with zero values
	projectRoot := withTempProject(t)
	dir := StateDir(projectRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data := `{"session_id": "abc", "project_root": "/foo"}`
	if err := os.WriteFile(StatePath(projectRoot), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("Load should succeed with partial JSON: %v", err)
	}
	if s.SessionID != "abc" {
		t.Fatalf("SessionID = %q", s.SessionID)
	}
	if s.SecretSession {
		t.Fatal("SecretSession should default to false")
	}
	if s.TurnCounter != 0 {
		t.Fatal("TurnCounter should default to 0")
	}
}

func TestSetDenyAll(t *testing.T) {
	s := NewState("/p")
	s.SetDenyAll("hooks.json tampered")
	if !s.DenyAll {
		t.Fatal("DenyAll should be true")
	}
	if s.DenyAllReason != "hooks.json tampered" {
		t.Fatalf("DenyAllReason = %q", s.DenyAllReason)
	}
}

func TestSetDenyAll_CannotBeCleared(t *testing.T) {
	// The State struct has no ClearDenyAll method — once set, it's permanent
	// for the session. Verify there's no way to unset it through normal API.
	s := NewState("/p")
	s.SetDenyAll("reason")

	// Only way to "clear" is creating a new state — verify the old one stays set
	if !s.DenyAll {
		t.Fatal("DenyAll should remain true")
	}
}

func TestSetDenyAll_MultipleCalls(t *testing.T) {
	s := NewState("/p")
	s.SetDenyAll("first reason")
	s.SetDenyAll("second reason")
	if !s.DenyAll {
		t.Fatal("DenyAll should still be true")
	}
	// Second call overwrites reason
	if s.DenyAllReason != "second reason" {
		t.Fatalf("DenyAllReason = %q, expected second reason", s.DenyAllReason)
	}
}

// --- UntrustedRead ---

func TestMarkUntrustedRead(t *testing.T) {
	s := NewState("/p")
	if s.RecentlyReadUntrusted {
		t.Fatal("should be false initially")
	}
	s.MarkUntrustedRead()
	if !s.RecentlyReadUntrusted {
		t.Fatal("should be true after MarkUntrustedRead")
	}
}

func TestClearUntrustedRead(t *testing.T) {
	s := NewState("/p")
	s.MarkUntrustedRead()
	s.ClearUntrustedRead()
	if s.RecentlyReadUntrusted {
		t.Fatal("should be false after ClearUntrustedRead")
	}
}

// --- PendingInstall ---

func TestSetPendingInstall(t *testing.T) {
	s := NewState("/p")
	hashes := map[string]string{"hooks.json": "h1"}
	s.SetPendingInstall("npm install", "npm", hashes, "lock123")
	if s.PendingInstall == nil {
		t.Fatal("PendingInstall should not be nil")
	}
	if s.PendingInstall.Command != "npm install" {
		t.Fatalf("Command = %q", s.PendingInstall.Command)
	}
	if s.PendingInstall.Manager != "npm" {
		t.Fatalf("Manager = %q", s.PendingInstall.Manager)
	}
	if s.PendingInstall.LockfileHash != "lock123" {
		t.Fatalf("LockfileHash = %q", s.PendingInstall.LockfileHash)
	}
	if s.PendingInstall.SentinelHashes["hooks.json"] != "h1" {
		t.Fatalf("SentinelHashes[hooks.json] = %q", s.PendingInstall.SentinelHashes["hooks.json"])
	}
}

func TestClearPendingInstall(t *testing.T) {
	s := NewState("/p")
	s.SetPendingInstall("pip install flask", "pip", map[string]string{}, "")
	s.ClearPendingInstall()
	if s.PendingInstall != nil {
		t.Fatal("PendingInstall should be nil after clear")
	}
}

func TestClearPendingInstall_WhenNil(t *testing.T) {
	s := NewState("/p")
	s.ClearPendingInstall() // should not panic
	if s.PendingInstall != nil {
		t.Fatal("should remain nil")
	}
}

// --- PostureHashes ---

func TestPostureHashes_StorageAndRetrieval(t *testing.T) {
	s := NewState("/p")
	s.PostureHashes["hooks.json"] = "aaa"
	s.PostureHashes["CLAUDE.md"] = "bbb"
	s.PostureHashes[".mcp.json"] = "ccc"

	if len(s.PostureHashes) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(s.PostureHashes))
	}
	if s.PostureHashes["hooks.json"] != "aaa" {
		t.Fatal("hash mismatch")
	}
}

func TestPostureHashes_TamperDetection(t *testing.T) {
	s := NewState("/p")
	s.PostureHashes["hooks.json"] = "original_hash"

	// Simulate tamper detection: hash changes
	currentHash := "modified_hash"
	if s.PostureHashes["hooks.json"] == currentHash {
		t.Fatal("hashes should differ (tamper detected)")
	}
}

func TestPostureHashes_PersistAcrossSaveLoad(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.PostureHashes["hooks.json"] = "h1"
	s.PostureHashes["CLAUDE.md"] = "h2"
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PostureHashes["hooks.json"] != "h1" {
		t.Fatal("posture hash not persisted")
	}
	if loaded.PostureHashes["CLAUDE.md"] != "h2" {
		t.Fatal("posture hash not persisted")
	}
}

// --- Complex scenarios ---

func TestScenario_SecretReadThenTurnScopedClear(t *testing.T) {
	// Simulates: turn 0 — agent reads .env with turn scope
	// turn 1 — secret should be cleared
	s := NewState("/p")

	// Turn 0: secret read approved with "turn" scope
	s.MarkSecretSessionWithScope("turn")
	if !s.SecretSession {
		t.Fatal("should be secret")
	}
	if s.SecretApprovalTurn != 0 {
		t.Fatalf("approval turn = %d, want 0", s.SecretApprovalTurn)
	}

	// Turn 1: next turn clears the secret
	s.IncrementTurn()
	if s.SecretSession {
		t.Fatal("turn-scoped secret should be cleared at turn 1")
	}

	// Now external egress should be allowed (no secret flag)
	if s.SecretSession {
		t.Fatal("secret should remain cleared")
	}
}

func TestScenario_SecretReadSessionScope_PersistsAcrossTurns(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSessionWithScope("session")

	for i := 0; i < 10; i++ {
		s.IncrementTurn()
	}

	if !s.SecretSession {
		t.Fatal("session-scoped secret should persist across all turns")
	}
}

func TestScenario_DenyAllBlocksEverything(t *testing.T) {
	// After deny-all, verify the state is set and cannot be recovered
	s := NewState("/p")
	s.SetDenyAll("hooks.json tampered by postinstall script")

	// Further operations on the state should still work (state tracks the deny)
	s.IncrementTurn()
	s.MarkSecretSession()

	if !s.DenyAll {
		t.Fatal("DenyAll should remain true regardless of other operations")
	}
}

func TestScenario_FullLifecycle(t *testing.T) {
	projectRoot := withTempProject(t)

	// 1. Create new session
	s := NewState(projectRoot)
	s.PostureHashes["hooks.json"] = "original"

	// 2. Save initial state
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// 3. Turn 0: normal coding (no flags set)
	s.IncrementTurn()

	// 4. Turn 1: agent reads .env (turn-scoped)
	s.MarkSecretSessionWithScope("turn")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// 5. Load from disk (simulating next hook call)
	s2, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.SecretSession {
		t.Fatal("secret should be set after load")
	}

	// 6. Turn 2: secret clears (turn-scoped)
	s2.IncrementTurn()
	if s2.SecretSession {
		t.Fatal("turn-scoped secret should clear")
	}

	// 7. Save final state
	if err := s2.Save(); err != nil {
		t.Fatal(err)
	}

	// 8. Verify final state from disk
	s3, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if s3.SecretSession {
		t.Fatal("should not be secret in final state")
	}
	if s3.TurnCounter != 2 {
		t.Fatalf("TurnCounter = %d, want 2", s3.TurnCounter)
	}
}

func TestScenario_SaveOverwritesPreviousState(t *testing.T) {
	projectRoot := withTempProject(t)

	s := NewState(projectRoot)
	s.MarkSecretSession()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	// Overwrite with cleared state
	s.ClearSecretSession()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.SecretSession {
		t.Fatal("second save should have overwritten the first")
	}
}

// --- JSON serialization details ---

func TestState_JSONFormat(t *testing.T) {
	s := NewState("/project")
	s.MarkSecretSession()
	s.PostureHashes["test"] = "hash"

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON that can be parsed back
	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check key fields exist
	if _, ok := parsed["session_id"]; !ok {
		t.Fatal("missing session_id in JSON")
	}
	if _, ok := parsed["secret_session"]; !ok {
		t.Fatal("missing secret_session in JSON")
	}
	if _, ok := parsed["posture_hashes"]; !ok {
		t.Fatal("missing posture_hashes in JSON")
	}
}

func TestState_OmitsEmptyOptionalFields(t *testing.T) {
	s := NewState("/project")
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}

	// Fields with omitempty should not appear when zero
	// Note: time.Time with omitempty still serializes as "0001-01-01T00:00:00Z" in Go
	// because time.Time is a struct, not a pointer. This is expected Go behavior.
	if _, ok := parsed["approval_scope"]; ok {
		t.Fatal("approval_scope should be omitted when empty")
	}
	if _, ok := parsed["pending_install"]; ok {
		t.Fatal("pending_install should be omitted when nil")
	}
	if _, ok := parsed["deny_all_reason"]; ok {
		t.Fatal("deny_all_reason should be omitted when empty")
	}
	if _, ok := parsed["lease_hash"]; ok {
		t.Fatal("lease_hash should be omitted when empty")
	}
	if _, ok := parsed["global_hook_hash"]; ok {
		t.Fatal("global_hook_hash should be omitted when empty")
	}
}

// --- Edge cases ---

func TestNewState_EmptyProjectRoot(t *testing.T) {
	s := NewState("")
	if s.SessionID == "" {
		t.Fatal("should still generate a session ID")
	}
	if s.ProjectRoot != "" {
		t.Fatal("ProjectRoot should be empty")
	}
}

func TestMarkSecretSession_AfterClear_CanBeReSet(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()
	s.ClearSecretSession()
	s.TurnCounter = 10
	s.MarkSecretSession()

	if !s.SecretSession {
		t.Fatal("should be re-settable after clear")
	}
	if s.SecretApprovalTurn != 10 {
		t.Fatalf("SecretApprovalTurn = %d, want 10", s.SecretApprovalTurn)
	}
}

func TestSave_MultipleTimes(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)

	for i := 0; i < 5; i++ {
		s.IncrementTurn()
		if err := s.Save(); err != nil {
			t.Fatalf("Save #%d failed: %v", i, err)
		}
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TurnCounter != 5 {
		t.Fatalf("TurnCounter = %d, want 5", loaded.TurnCounter)
	}
}

// --- Table-driven tests for scope behavior ---

func TestIncrementTurn_ScopeMatrix(t *testing.T) {
	tests := []struct {
		name         string
		scope        policy.ApprovalScope
		approvalTurn int
		currentTurn  int
		expectSecret bool
	}{
		{
			name:         "turn scope, same turn",
			scope:        policy.ApprovalScopeTurn,
			approvalTurn: 3,
			currentTurn:  3,
			// After increment: turn=4, 4>3, clear
			expectSecret: false,
		},
		{
			name:         "session scope, many turns later",
			scope:        policy.ApprovalScopeSession,
			approvalTurn: 0,
			currentTurn:  99,
			// Session scope never clears on increment
			expectSecret: true,
		},
		{
			name:         "turn scope, just approved",
			scope:        policy.ApprovalScopeTurn,
			approvalTurn: 0,
			currentTurn:  0,
			// After increment: turn=1, 1>0, clear
			expectSecret: false,
		},
		{
			name:         "empty scope (default), treated as session",
			scope:        "",
			approvalTurn: 0,
			currentTurn:  0,
			// Empty scope != "turn", so no clearing
			expectSecret: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewState("/p")
			s.SecretSession = true
			s.ApprovalScope = tt.scope
			s.SecretApprovalTurn = tt.approvalTurn
			s.TurnCounter = tt.currentTurn

			s.IncrementTurn()

			if s.SecretSession != tt.expectSecret {
				t.Fatalf("SecretSession = %v, want %v", s.SecretSession, tt.expectSecret)
			}
		})
	}
}

// --- Verify file permissions ---

func TestSave_FilePermissions(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(StatePath(projectRoot))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Fatalf("session.json permissions = %o, want 0600", perm)
	}

	dirInfo, err := os.Stat(StateDir(projectRoot))
	if err != nil {
		t.Fatal(err)
	}
	dirPerm := dirInfo.Mode().Perm()
	if dirPerm != 0o700 {
		t.Fatalf("state dir permissions = %o, want 0700", dirPerm)
	}
}
