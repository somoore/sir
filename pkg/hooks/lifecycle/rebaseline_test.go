package lifecycle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func TestRebaselineAllProjects_RefreshesHashesAndClearsHookInducedDenyAll(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Hook-induced deny — install rewrote ~/.claude/settings.json; stale
	// baseline should be refreshed and deny_all cleared.
	tampered := seedProject(t, home, "tampered", func(s *session.State) {
		s.SetDenyAll("posture file tampered: ~/.claude/settings.json")
	})

	// Non-hook deny — must be preserved, though hashes are still refreshed.
	secret := seedProject(t, home, "secret", func(s *session.State) {
		s.SetDenyAll("secret session: .env read without approval")
	})

	// No deny, but stale posture hash (simulates a healthy session that was
	// alive across the upgrade).
	clean := seedProject(t, home, "clean", nil)
	staleHashes := map[string]string{".claude/settings.json": "deadbeef"}
	if err := session.Update(clean.projectRoot, func(s *session.State) error {
		s.PostureHashes = staleHashes
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Rewrite the global hook file post-seed to force baseline drift.
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"command":"sir guard evaluate"}]}]}}`)

	summary, err := RebaselineAllProjects()
	if err != nil {
		t.Fatalf("RebaselineAllProjects: %v", err)
	}
	if summary.Refreshed != 3 {
		t.Errorf("Refreshed = %d, want 3 (skipped = %+v)", summary.Refreshed, summary.Skipped)
	}
	if summary.DenyAllCleared != 1 {
		t.Errorf("DenyAllCleared = %d, want 1 (only the hook-induced one)", summary.DenyAllCleared)
	}

	// Tampered project: deny_all cleared, hashes match current on-disk file.
	got, err := session.Load(tampered.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got.DenyAll {
		t.Errorf("tampered: deny_all still set after rebaseline (reason=%q)", got.DenyAllReason)
	}
	if got.DenyAllReason != "" {
		t.Errorf("tampered: deny_all_reason = %q, want empty", got.DenyAllReason)
	}
	wantHashes := posture.HashSentinelFiles(tampered.projectRoot, tampered.lease.PostureFiles)
	if got.PostureHashes[".claude/settings.json"] != wantHashes[".claude/settings.json"] {
		t.Errorf("tampered: posture hash not refreshed\n got  = %q\n want = %q",
			got.PostureHashes[".claude/settings.json"], wantHashes[".claude/settings.json"])
	}

	// Secret project: deny_all preserved, hashes still refreshed.
	got, err = session.Load(secret.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DenyAll {
		t.Error("secret: deny_all should remain set (non-hook-induced reason)")
	}
	if got.DenyAllReason != "secret session: .env read without approval" {
		t.Errorf("secret: deny_all_reason = %q, want original", got.DenyAllReason)
	}
	if got.PostureHashes[".claude/settings.json"] == "" {
		t.Error("secret: posture hashes should still be refreshed even when deny stays")
	}

	// Clean project: stale fake hash replaced with real one.
	got, err = session.Load(clean.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got.PostureHashes[".claude/settings.json"] == "deadbeef" {
		t.Error("clean: stale posture hash not refreshed")
	}
}

func TestRebaselineAllProjects_SkipsMismatchedProjectRoot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	writeClaudeSettings(t, home, `{"hooks":{}}`)

	// Put a session.json under a directory whose name does NOT match the hash
	// of its project_root. RebaselineAllProjects must skip rather than silently
	// write a fresh session to a different directory.
	wrongDir := filepath.Join(home, ".sir", "projects", "0000000000000000000000000000000000000000000000000000000000000000")
	if err := os.MkdirAll(wrongDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionJSON := []byte(`{"schema_version":1,"project_root":"/tmp/some-other-path","deny_all":true,"deny_all_reason":"posture file tampered: x"}`)
	if err := os.WriteFile(filepath.Join(wrongDir, "session.json"), sessionJSON, 0o600); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	if err := l.Save(filepath.Join(wrongDir, "lease.json")); err != nil {
		t.Fatal(err)
	}

	summary, err := RebaselineAllProjects()
	if err != nil {
		t.Fatalf("RebaselineAllProjects: %v", err)
	}
	if summary.Refreshed != 0 {
		t.Errorf("Refreshed = %d, want 0 for mismatched state", summary.Refreshed)
	}
	if len(summary.Skipped) != 1 {
		t.Fatalf("Skipped = %+v, want exactly one mismatch entry", summary.Skipped)
	}
}

func TestRebaselineAllProjects_NoProjectsDirIsNotError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	summary, err := RebaselineAllProjects()
	if err != nil {
		t.Fatalf("RebaselineAllProjects: %v", err)
	}
	if summary.Refreshed != 0 || summary.DenyAllCleared != 0 || len(summary.Skipped) != 0 {
		t.Errorf("fresh home should yield zero-valued summary; got %+v", summary)
	}
}

func TestIsHookInducedDenyReason(t *testing.T) {
	cases := []struct {
		reason string
		want   bool
	}{
		// Hook-induced — all emitted verbatim from pkg/hooks/*
		{"posture file tampered: ~/.claude/settings.json", true},
		{"posture file tampered: ~/.codex/hooks.json, ~/.gemini/settings.json", true},
		{"posture tampered before delegation: [.claude/settings.json]", true},
		{"managed hook baseline unavailable: policy missing", true},
		{"managed hook baseline unavailable during config change: policy missing", true},
		{"global hooks file tampered: ~/.claude/settings.json", true},
		{"global hooks modified during config change: ~/.claude/settings.json", true},

		// Not hook-induced — install must preserve these denies
		{"secret session: .env read without approval", false},
		{"session.json modified outside sir", false},
		{"lease.json modified outside approved write", false},
		{"runtime containment stale", false},

		// No match for historical / no-longer-emitted shapes
		{"managed hooks tampered: PreToolUse", false}, // was in the old prefix list; never emitted
		{"managed hook", false},                       // too-broad prefix removed

		{"", false},
		{"   ", false},
	}
	for _, tc := range cases {
		if got := isHookInducedDenyReason(tc.reason); got != tc.want {
			t.Errorf("isHookInducedDenyReason(%q) = %v, want %v", tc.reason, got, tc.want)
		}
	}
}

// --- helpers ---

type seededProject struct {
	projectRoot string
	lease       *lease.Lease
}

// seedProject builds a project state directory under HOME, writes a lease and
// an initial session.json, then applies an optional mutator. Returns the
// project root path so tests can re-load and assert.
func seedProject(t *testing.T, home, name string, mutate func(*session.State)) seededProject {
	t.Helper()
	projectRoot := filepath.Join(home, "projects", name)
	if err := os.MkdirAll(projectRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(home, ".sir", "projects", session.ProjectHash(projectRoot))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	l := lease.DefaultLease()
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		t.Fatal(err)
	}
	// Seed an initial session baseline against whatever settings.json exists now.
	writeClaudeSettings(t, home, `{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"command":"sir guard evaluate OLD"}]}]}}`)
	state := session.NewState(projectRoot)
	state.PostureHashes = posture.HashSentinelFiles(projectRoot, l.PostureFiles)
	if hash, err := posture.HashGlobalHooksFile(); err == nil {
		state.GlobalHookHash = hash
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		if err := session.Update(projectRoot, func(s *session.State) error {
			mutate(s)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	return seededProject{projectRoot: projectRoot, lease: l}
}

func writeClaudeSettings(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Validate JSON so we catch typos in fixtures early.
	var probe any
	if err := json.Unmarshal([]byte(body), &probe); err != nil {
		t.Fatalf("writeClaudeSettings: body is not valid JSON: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "settings.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
