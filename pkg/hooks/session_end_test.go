// session_end_test.go — Regression guard for the Codex single-turn
// apply_patch blind spot.
//
// Background: Codex-cli 0.118 does not fire PreToolUse for apply_patch
// (documented in docs/user/codex-support.md). The compensating control was
// "PostToolUse sentinel re-hash" — but in a one-shot `codex exec` run
// there is no next PostToolUse, so the write is invisible until the
// test discovered it (codex-evil-findings.md C7).
//
// Fix R1 from codex-evil-findings.md: run the sentinel sweep one last
// time in SessionEnd so the single-turn blind spot is closed.
//
// This test exercises that fix end-to-end through the real
// EvaluateSessionEnd hook handler using a pipe-based stdin mock (same
// pattern parity_test.go uses).
package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// TestSessionEnd_PostureSweep_CatchesSingleTurnApplyPatchWrite verifies
// that when a posture file is modified during a session but no further
// PostToolUse ever runs (the single-turn `codex exec` case), the
// SessionEnd handler still detects the drift and appends a
// `posture_change` alert to the ledger.
func TestSessionEnd_PostureSweep_CatchesSingleTurnApplyPatchWrite(t *testing.T) {
	projectRoot := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	// Seed: a CLAUDE.md posture file with known content.
	claudeMd := filepath.Join(projectRoot, "CLAUDE.md")
	if err := os.WriteFile(claudeMd, []byte("# original instructions\n"), 0o644); err != nil {
		t.Fatalf("seed CLAUDE.md: %v", err)
	}

	// Seed a lease that includes CLAUDE.md in its PostureFiles list
	// (which is the default anyway — lease.DefaultLease() lists it).
	l := lease.DefaultLease()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	leasePath := filepath.Join(stateDir, "lease.json")
	leaseBytes, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal lease: %v", err)
	}
	if err := os.WriteFile(leasePath, leaseBytes, 0o600); err != nil {
		t.Fatalf("write lease: %v", err)
	}

	// Initialize session state with the ORIGINAL posture hash captured.
	// This simulates what SessionStart would have done if the user had
	// run `codex exec` on a clean workspace.
	st := session.NewState(projectRoot)
	st.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	if err := st.Save(); err != nil {
		t.Fatalf("save initial state: %v", err)
	}

	// Tamper: simulate Codex apply_patch writing new content to CLAUDE.md
	// without firing any PreToolUse or PostToolUse hook. This is the
	// exact scenario that motivated R1 — the write is invisible to all
	// normal hook events.
	if err := os.WriteFile(claudeMd, []byte("# injected instructions\n"), 0o644); err != nil {
		t.Fatalf("simulate apply_patch write: %v", err)
	}

	// Count ledger entries before SessionEnd so we can assert on the
	// delta. A fresh project has no ledger entries yet.
	beforeEntries, _ := ledger.ReadAll(projectRoot)
	beforeCount := len(beforeEntries)

	// Fire SessionEnd via the real entry point. Pipe a minimal payload
	// through os.Stdin, same pattern parity_test.go uses.
	payload := []byte(`{"hook_event_name":"SessionEnd","session_id":"test-session"}`)
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdin = r
	if _, err := w.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	w.Close()

	if err := EvaluateSessionEnd(projectRoot, agent.NewCodexAgent()); err != nil {
		t.Fatalf("EvaluateSessionEnd returned error: %v", err)
	}

	// Assert: the ledger gained at least two entries — one
	// posture_change alert + one session_end closing entry.
	afterEntries, readErr := ledger.ReadAll(projectRoot)
	if readErr != nil {
		t.Fatalf("ledger.ReadAll after: %v", readErr)
	}
	delta := len(afterEntries) - beforeCount
	if delta < 2 {
		t.Fatalf("expected >=2 new ledger entries (posture_change + session_end), got %d", delta)
	}

	// Walk the new entries and confirm at least one is a
	// posture_change alert targeting CLAUDE.md with the correct
	// alert_type.
	var foundAlert bool
	for _, e := range afterEntries[beforeCount:] {
		if e.Verb != "posture_change" {
			continue
		}
		if !strings.Contains(e.Target, "CLAUDE.md") {
			t.Errorf("posture_change alert targets %q, want substring CLAUDE.md", e.Target)
		}
		if e.AlertType != "posture_change_session_end" {
			t.Errorf("posture_change alert_type = %q, want posture_change_session_end", e.AlertType)
		}
		if e.Decision != "alert" {
			t.Errorf("posture_change decision = %q, want alert", e.Decision)
		}
		foundAlert = true
	}
	if !foundAlert {
		t.Error("no posture_change alert found in session_end ledger entries — single-turn blind spot is still open")
	}
}

// TestSessionSummary_PostureSweep_CatchesCodexApplyPatchWrite is the
// load-bearing regression guard for codex-evil-findings.md R1. Codex
// fires Stop (routed through EvaluateSessionSummary) but NOT SessionEnd,
// so the sweep has to run inside the Stop handler for single-turn
// `codex exec` invocations to be covered. This test exercises that
// exact entry point.
func TestSessionSummary_PostureSweep_CatchesCodexApplyPatchWrite(t *testing.T) {
	projectRoot := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	claudeMd := filepath.Join(projectRoot, "CLAUDE.md")
	if err := os.WriteFile(claudeMd, []byte("# original\n"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	l := lease.DefaultLease()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	leaseBytes, _ := json.Marshal(l)
	if err := os.WriteFile(filepath.Join(stateDir, "lease.json"), leaseBytes, 0o600); err != nil {
		t.Fatalf("write lease: %v", err)
	}

	// Capture session-start posture hashes.
	st := session.NewState(projectRoot)
	st.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	if err := st.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Simulate apply_patch: write without firing any hook.
	if err := os.WriteFile(claudeMd, []byte("# injected by apply_patch\n"), 0o644); err != nil {
		t.Fatalf("simulate: %v", err)
	}

	beforeEntries, _ := ledger.ReadAll(projectRoot)
	beforeCount := len(beforeEntries)

	// Fire Stop via EvaluateSessionSummary (the real handler wired to
	// the Stop hook event for both Claude Code and Codex).
	payload := []byte(`{"hook_event_name":"Stop","session_id":"t","reason":"end_turn"}`)
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.Write(payload)
	w.Close()

	if err := EvaluateSessionSummary(projectRoot, agent.NewCodexAgent()); err != nil {
		t.Fatalf("EvaluateSessionSummary: %v", err)
	}

	afterEntries, _ := ledger.ReadAll(projectRoot)
	var foundAlert bool
	for _, e := range afterEntries[beforeCount:] {
		if e.Verb == "posture_change" && e.AlertType == "posture_change_session_end" {
			if !strings.Contains(e.Target, "CLAUDE.md") {
				t.Errorf("alert target = %q, want substring CLAUDE.md", e.Target)
			}
			foundAlert = true
			break
		}
	}
	if !foundAlert {
		t.Error("EvaluateSessionSummary did not raise posture_change alert — Codex single-turn blind spot still open")
	}
}

// TestSessionEnd_PostureSweep_NoDriftProducesNoAlert verifies the
// negative case: if posture files are unchanged between session start
// and session end, the sweep produces zero false positives.
func TestSessionEnd_PostureSweep_NoDriftProducesNoAlert(t *testing.T) {
	projectRoot := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	claudeMd := filepath.Join(projectRoot, "CLAUDE.md")
	if err := os.WriteFile(claudeMd, []byte("# instructions\n"), 0o644); err != nil {
		t.Fatalf("seed CLAUDE.md: %v", err)
	}

	l := lease.DefaultLease()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	leaseBytes, _ := json.Marshal(l)
	if err := os.WriteFile(filepath.Join(stateDir, "lease.json"), leaseBytes, 0o600); err != nil {
		t.Fatalf("write lease: %v", err)
	}

	st := session.NewState(projectRoot)
	st.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	if err := st.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	beforeEntries, _ := ledger.ReadAll(projectRoot)
	beforeCount := len(beforeEntries)

	payload := []byte(`{"hook_event_name":"SessionEnd","session_id":"test-session"}`)
	origStdin := os.Stdin
	defer func() { os.Stdin = origStdin }()
	r, w, _ := os.Pipe()
	os.Stdin = r
	_, _ = w.Write(payload)
	w.Close()

	if err := EvaluateSessionEnd(projectRoot, agent.NewCodexAgent()); err != nil {
		t.Fatalf("EvaluateSessionEnd: %v", err)
	}

	afterEntries, _ := ledger.ReadAll(projectRoot)
	// The only new entry should be the session_end closing row — no
	// posture_change alerts on an unchanged workspace.
	for _, e := range afterEntries[beforeCount:] {
		if e.Verb == "posture_change" {
			t.Errorf("false positive: posture_change alert on unchanged workspace: %+v", e)
		}
	}
}

// TestSessionEnd_PostureSweep_UsesGlobalGeminiSettingsNotProjectShadow proves
// the terminal sweep hashes ~/.gemini/settings.json, not a project-local
// shadow at .gemini/settings.json. A tampered global Gemini config must be
// detected even if the project tree contains a different file at the same
// relative path.
func TestSessionEnd_PostureSweep_UsesGlobalGeminiSettingsNotProjectShadow(t *testing.T) {
	projectRoot := t.TempDir()
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectShadow := filepath.Join(projectRoot, ".gemini", "settings.json")
	globalGemini := filepath.Join(tmpHome, ".gemini", "settings.json")
	for _, path := range []string{projectShadow, globalGemini} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
		}
	}
	if err := os.WriteFile(projectShadow, []byte(`{"hooks":{"BeforeTool":"project-shadow"}}`), 0o644); err != nil {
		t.Fatalf("write project shadow: %v", err)
	}
	if err := os.WriteFile(globalGemini, []byte(`{"hooks":{"BeforeTool":"global-original"}}`), 0o644); err != nil {
		t.Fatalf("write global gemini: %v", err)
	}

	l := lease.DefaultLease()
	l.PostureFiles = []string{".gemini/settings.json"}
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	leaseBytes, err := json.Marshal(l)
	if err != nil {
		t.Fatalf("marshal lease: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "lease.json"), leaseBytes, 0o600); err != nil {
		t.Fatalf("write lease: %v", err)
	}

	state := session.NewState(projectRoot)
	state.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	if err := state.Save(); err != nil {
		t.Fatalf("save state: %v", err)
	}

	if err := os.WriteFile(globalGemini, []byte(`{"hooks":{"BeforeTool":"global-tampered"}}`), 0o644); err != nil {
		t.Fatalf("tamper global gemini: %v", err)
	}

	beforeEntries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger before: %v", err)
	}
	beforeCount := len(beforeEntries)

	if err := runSessionTerminalPostureSweep(projectRoot); err != nil {
		t.Fatalf("runSessionTerminalPostureSweep: %v", err)
	}

	afterEntries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger after: %v", err)
	}
	var foundAlert bool
	for _, e := range afterEntries[beforeCount:] {
		if e.Verb != "posture_change" {
			continue
		}
		if e.Target != ".gemini/settings.json" {
			t.Fatalf("posture_change target = %q, want .gemini/settings.json", e.Target)
		}
		foundAlert = true
	}
	if !foundAlert {
		t.Fatal("session sweep did not detect Gemini drift; likely hashed the project-local shadow path")
	}

	projectShadowAfter, err := os.ReadFile(projectShadow)
	if err != nil {
		t.Fatalf("read project shadow: %v", err)
	}
	if string(projectShadowAfter) != `{"hooks":{"BeforeTool":"project-shadow"}}` {
		t.Fatalf("project-local shadow was modified unexpectedly: %s", projectShadowAfter)
	}
}
