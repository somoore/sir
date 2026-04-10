package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// --- ProjectHash ---

func TestProjectHash_Deterministic(t *testing.T) {
	h1 := ProjectHash("/foo/bar")
	h2 := ProjectHash("/foo/bar")
	if h1 != h2 {
		t.Fatalf("same input produced different hashes: %s vs %s", h1, h2)
	}
}

func TestProjectHash_DifferentInputs(t *testing.T) {
	h1 := ProjectHash("/foo/bar")
	h2 := ProjectHash("/foo/baz")
	if h1 == h2 {
		t.Fatal("different inputs produced same hash")
	}
}

func TestProjectHash_Length(t *testing.T) {
	h := ProjectHash("/anything")
	// SHA-256 hex = 64 chars
	if len(h) != 64 {
		t.Fatalf("expected 64 char hex hash, got %d chars: %s", len(h), h)
	}
}

// --- StateDir / StatePath ---

func TestStateDir_ContainsProjectHash(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	dir := StateDir("/myproject")
	hash := ProjectHash("/myproject")
	if !filepath.IsAbs(dir) {
		t.Fatal("StateDir should return absolute path")
	}
	if filepath.Base(dir) != hash {
		t.Fatalf("expected dir to end with project hash %s, got %s", hash, filepath.Base(dir))
	}
}

func TestStatePath_EndsWithSessionJSON(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	p := StatePath("/myproject")
	if filepath.Base(p) != "session.json" {
		t.Fatalf("expected session.json, got %s", filepath.Base(p))
	}
}

func TestStateDir_UsesOverrideHome(t *testing.T) {
	tmpHome := t.TempDir()
	overrideHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(StateHomeEnvVar, overrideHome)

	dir := StateDir("/myproject")
	if !strings.HasPrefix(dir, overrideHome+string(filepath.Separator)) {
		t.Fatalf("StateDir = %q, want prefix %q when %s is set", dir, overrideHome, StateHomeEnvVar)
	}
}

func TestDurableStateDir_IgnoresOverrideHome(t *testing.T) {
	tmpHome := t.TempDir()
	overrideHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	t.Setenv(StateHomeEnvVar, overrideHome)

	dir := DurableStateDir("/myproject")
	if !strings.HasPrefix(dir, filepath.Join(tmpHome, ".sir")+string(filepath.Separator)) {
		t.Fatalf("DurableStateDir = %q, want real HOME prefix %q", dir, tmpHome)
	}
}

// --- NewState ---

func TestNewState_InitialValues(t *testing.T) {
	s := NewState("/project")

	if s.SessionID == "" {
		t.Fatal("SessionID should not be empty")
	}
	if len(s.SessionID) != 16 {
		t.Fatalf("SessionID should be 16 chars, got %d: %s", len(s.SessionID), s.SessionID)
	}
	if s.ProjectRoot != "/project" {
		t.Fatalf("ProjectRoot = %q, want /project", s.ProjectRoot)
	}
	if s.StartedAt.IsZero() {
		t.Fatal("StartedAt should not be zero")
	}
	if s.SecretSession {
		t.Fatal("SecretSession should be false initially")
	}
	if s.DenyAll {
		t.Fatal("DenyAll should be false initially")
	}
	if s.TurnCounter != 0 {
		t.Fatalf("TurnCounter should be 0, got %d", s.TurnCounter)
	}
	if s.PostureHashes == nil {
		t.Fatal("PostureHashes should be initialized (not nil)")
	}
	if len(s.PostureHashes) != 0 {
		t.Fatal("PostureHashes should be empty initially")
	}
	if s.ApprovalScope != "" {
		t.Fatalf("ApprovalScope should be empty, got %q", s.ApprovalScope)
	}
	if s.RecentlyReadUntrusted {
		t.Fatal("RecentlyReadUntrusted should be false initially")
	}
	if s.PendingInstall != nil {
		t.Fatal("PendingInstall should be nil initially")
	}
}

func TestNewState_UniqueSessionIDs(t *testing.T) {
	// Different project roots should produce different session IDs
	s1 := NewState("/project-a")
	s2 := NewState("/project-b")
	if s1.SessionID == s2.SessionID {
		t.Fatal("different projects should have different session IDs")
	}
}

// --- Save / Load round-trip ---

func TestSave_CreatesDirectoryAndFile(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	path := StatePath(projectRoot)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("session.json not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}

	// Directory should be 0700
	dirInfo, err := os.Stat(StateDir(projectRoot))
	if err != nil {
		t.Fatalf("state dir not created: %v", err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("expected 0700 dir permissions, got %o", dirInfo.Mode().Perm())
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.PostureHashes["hooks.json"] = "abc123"
	s.PostureHashes["CLAUDE.md"] = "def456"
	s.LeaseHash = "leasehash"
	s.GlobalHookHash = "globalhookhash"

	if err := s.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.SessionID != s.SessionID {
		t.Fatalf("SessionID mismatch: %q vs %q", loaded.SessionID, s.SessionID)
	}
	if loaded.ProjectRoot != s.ProjectRoot {
		t.Fatalf("ProjectRoot mismatch")
	}
	if loaded.LeaseHash != "leasehash" {
		t.Fatalf("LeaseHash mismatch: %q", loaded.LeaseHash)
	}
	if loaded.GlobalHookHash != "globalhookhash" {
		t.Fatalf("GlobalHookHash mismatch: %q", loaded.GlobalHookHash)
	}
	if len(loaded.PostureHashes) != 2 {
		t.Fatalf("PostureHashes count = %d, want 2", len(loaded.PostureHashes))
	}
	if loaded.PostureHashes["hooks.json"] != "abc123" {
		t.Fatalf("PostureHashes[hooks.json] = %q", loaded.PostureHashes["hooks.json"])
	}
}

func TestSaveLoad_SecretSessionPersists(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.MarkSecretSession()

	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.SecretSession {
		t.Fatal("SecretSession should persist across Save/Load")
	}
	if loaded.SecretSessionSince.IsZero() {
		t.Fatal("SecretSessionSince should persist")
	}
	if loaded.ApprovalScope != policy.ApprovalScopeTurn {
		t.Fatalf("ApprovalScope should be 'turn' (default), got %q", loaded.ApprovalScope)
	}
}

func TestSaveLoad_DenyAllPersists(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.SetDenyAll("tampered hooks.json")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.DenyAll {
		t.Fatal("DenyAll should persist")
	}
	if loaded.DenyAllReason != "tampered hooks.json" {
		t.Fatalf("DenyAllReason = %q", loaded.DenyAllReason)
	}
}

func TestSaveLoad_TurnCounterPersists(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.IncrementTurn()
	s.IncrementTurn()
	s.IncrementTurn()
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.TurnCounter != 3 {
		t.Fatalf("TurnCounter = %d, want 3", loaded.TurnCounter)
	}
}

func TestSaveLoad_PendingInstallPersists(t *testing.T) {
	projectRoot := withTempProject(t)
	s := NewState(projectRoot)
	s.SetPendingInstall("npm install express", "npm",
		map[string]string{"hooks.json": "h1", "CLAUDE.md": "h2"},
		"lockfilehash")
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.PendingInstall == nil {
		t.Fatal("PendingInstall should persist")
	}
	if loaded.PendingInstall.Command != "npm install express" {
		t.Fatalf("PendingInstall.Command = %q", loaded.PendingInstall.Command)
	}
	if loaded.PendingInstall.Manager != "npm" {
		t.Fatalf("PendingInstall.Manager = %q", loaded.PendingInstall.Manager)
	}
	if loaded.PendingInstall.LockfileHash != "lockfilehash" {
		t.Fatalf("PendingInstall.LockfileHash = %q", loaded.PendingInstall.LockfileHash)
	}
	if len(loaded.PendingInstall.SentinelHashes) != 2 {
		t.Fatalf("SentinelHashes count = %d", len(loaded.PendingInstall.SentinelHashes))
	}
}

// --- Load error cases ---
