package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func writeCorruptSessionFile(t *testing.T, projectRoot string) {
	t.Helper()
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(session.StateDir(projectRoot), "session.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeInvalidLeaseFile(t *testing.T, projectRoot string) {
	t.Helper()
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(session.StateDir(projectRoot), "lease.json"), []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeValidSessionFile(t *testing.T, projectRoot string) {
	t.Helper()
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestEvaluateConfigChange_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"ConfigChange","config_key":"hooks"}`, func() {
		gotErr = EvaluateConfigChange(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateConfigChange_InvalidLeaseFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeValidSessionFile(t, projectRoot)
	writeInvalidLeaseFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"ConfigChange","config_key":"hooks"}`, func() {
		gotErr = EvaluateConfigChange(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected invalid lease to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load lease") {
		t.Fatalf("expected load lease error, got %v", gotErr)
	}
}

func TestEvaluateUserPrompt_MissingSessionStillSucceeds(t *testing.T) {
	projectRoot := t.TempDir()

	var gotErr error
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"UserPromptSubmit"}`, func() {
		gotErr = EvaluateUserPrompt(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr != nil {
		t.Fatalf("missing session should remain a no-op, got %v", gotErr)
	}
}

func TestEvaluateUserPrompt_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"UserPromptSubmit"}`, func() {
		gotErr = EvaluateUserPrompt(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateInstructionsLoaded_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	payload := `{"session_id":"sess-1","hook_event_name":"InstructionsLoaded","file_path":"` + filepath.Join(projectRoot, "CLAUDE.md") + `","content":"# rules"}`
	var gotErr error
	withTestStdin(t, payload, func() {
		gotErr = EvaluateInstructionsLoaded(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestPostEvaluate_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	payload := `{"session_id":"sess-1","hook_event_name":"PostToolUse","tool_name":"Read","tool_use_id":"toolu_1","tool_output":"ok","cwd":"` + projectRoot + `"}`
	var gotErr error
	withTestStdin(t, payload, func() {
		gotErr = PostEvaluate(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateSessionSummary_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"hook_event_name":"Stop","session_id":"sess-1","reason":"end_turn"}`, func() {
		gotErr = EvaluateSessionSummary(projectRoot, agent.NewCodexAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateSessionEnd_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"hook_event_name":"SessionEnd","session_id":"sess-1"}`, func() {
		gotErr = EvaluateSessionEnd(projectRoot, agent.NewCodexAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateSessionEnd_InvalidLeaseFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeValidSessionFile(t, projectRoot)
	writeInvalidLeaseFile(t, projectRoot)

	var gotErr error
	withTestStdin(t, `{"hook_event_name":"SessionEnd","session_id":"sess-1"}`, func() {
		gotErr = EvaluateSessionEnd(projectRoot, agent.NewCodexAgent())
	})
	if gotErr == nil {
		t.Fatal("expected invalid lease to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load lease") {
		t.Fatalf("expected load lease error, got %v", gotErr)
	}
}

func TestEvaluateCompactReinject_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	before, err := os.ReadFile(filepath.Join(session.StateDir(projectRoot), "session.json"))
	if err != nil {
		t.Fatalf("read corrupt session: %v", err)
	}

	var gotErr error
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"SessionStart"}`, func() {
		gotErr = EvaluateCompactReinject(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt compact-reinject session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}

	after, err := os.ReadFile(filepath.Join(session.StateDir(projectRoot), "session.json"))
	if err != nil {
		t.Fatalf("re-read corrupt session: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("corrupt session.json should be preserved for investigation, not overwritten")
	}
}

func TestEvaluateCompactReinject_MissingSessionBootstrapsBaseline(t *testing.T) {
	projectRoot := t.TempDir()

	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"SessionStart"}`, func() {
		if err := EvaluateCompactReinject(projectRoot, agent.NewClaudeAgent()); err != nil {
			t.Fatalf("EvaluateCompactReinject: %v", err)
		}
	})

	if _, err := session.Load(projectRoot); err != nil {
		t.Fatalf("expected compact-reinject to bootstrap missing session baseline: %v", err)
	}
}

func TestEvaluateElicitation_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	payload := `{"session_id":"sess-1","hook_event_name":"Elicitation","message":"Please paste your API key","tool_use_id":"toolu_1","cwd":"` + projectRoot + `"}`
	var gotErr error
	withTestStdin(t, payload, func() {
		gotErr = EvaluateElicitation(projectRoot, agent.NewClaudeAgent())
	})
	if gotErr == nil {
		t.Fatal("expected corrupt elicitation session to fail closed")
	}
	if !strings.Contains(gotErr.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", gotErr)
	}
}

func TestEvaluateElicitation_MissingSessionBootstrapsAndRaisesPosture(t *testing.T) {
	projectRoot := t.TempDir()

	payload := `{"session_id":"sess-1","hook_event_name":"Elicitation","message":"Please paste your API key","tool_use_id":"toolu_1","cwd":"` + projectRoot + `"}`
	withTestStdin(t, payload, func() {
		if err := EvaluateElicitation(projectRoot, agent.NewClaudeAgent()); err != nil {
			t.Fatalf("EvaluateElicitation: %v", err)
		}
	})

	state, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("load session after elicitation: %v", err)
	}
	if state.Posture != policy.PostureStateElevated {
		t.Fatalf("posture = %q, want %q", state.Posture, policy.PostureStateElevated)
	}
}

func TestSessionStartFloor_CorruptSessionFailsClosed(t *testing.T) {
	projectRoot := t.TempDir()
	writeCorruptSessionFile(t, projectRoot)

	_, err := sessionStartFloor(projectRoot, "session-summary")
	if err == nil {
		t.Fatal("expected corrupt sessionStartFloor load to fail closed")
	}
	if !strings.Contains(err.Error(), "load session") {
		t.Fatalf("expected load session error, got %v", err)
	}
}

func TestSessionStartFloor_MissingSessionReturnsZeroTime(t *testing.T) {
	projectRoot := t.TempDir()

	floor, err := sessionStartFloor(projectRoot, "session-summary")
	if err != nil {
		t.Fatalf("sessionStartFloor: %v", err)
	}
	if !floor.IsZero() {
		t.Fatalf("expected zero time for missing session, got %v", floor)
	}
}
