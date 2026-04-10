package hooks

import (
	"os"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// HandleUserPrompt processes a Notification hook for user messages.
// It advances the turn counter, which may clear turn-scoped secrets.
func HandleUserPrompt(state *session.State) error {
	if state == nil {
		return nil
	}
	state.IncrementTurn()
	return nil
}

// --- Tests ---

func TestUserPrompt_AdvancesTurnCounter(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	if state.TurnCounter != 0 {
		t.Fatalf("initial turn counter should be 0, got %d", state.TurnCounter)
	}

	if err := HandleUserPrompt(state); err != nil {
		t.Fatalf("HandleUserPrompt: %v", err)
	}
	if state.TurnCounter != 1 {
		t.Errorf("expected turn counter 1 after first prompt, got %d", state.TurnCounter)
	}

	if err := HandleUserPrompt(state); err != nil {
		t.Fatalf("HandleUserPrompt: %v", err)
	}
	if state.TurnCounter != 2 {
		t.Errorf("expected turn counter 2 after second prompt, got %d", state.TurnCounter)
	}
}

func TestUserPrompt_ClearsTurnScopedSecret(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)

	// Mark secret with turn scope at turn 0
	state.MarkSecretSessionWithScope("turn")
	if !state.SecretSession {
		t.Fatal("SecretSession should be true after MarkSecretSessionWithScope")
	}

	// Simulate some time passing so MaybeAdvanceTurn would fire,
	// but use IncrementTurn directly (which HandleUserPrompt calls)
	if err := HandleUserPrompt(state); err != nil {
		t.Fatal(err)
	}

	// Turn counter is now 1, secret was approved at turn 0 with "turn" scope
	// The turn has advanced past the approval turn, so secret should be cleared
	if state.SecretSession {
		t.Error("expected SecretSession to be cleared after turn advances past approval turn")
	}
}

func TestUserPrompt_PreservesSessionScopedSecret(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)

	// Mark secret with session scope
	state.MarkSecretSessionWithScope("session")
	if !state.SecretSession {
		t.Fatal("SecretSession should be true")
	}

	// Advance multiple turns
	for i := 0; i < 5; i++ {
		if err := HandleUserPrompt(state); err != nil {
			t.Fatal(err)
		}
	}

	// Session-scoped secrets must NOT be cleared by turn advancement
	if !state.SecretSession {
		t.Error("expected session-scoped SecretSession to persist across turn boundaries")
	}
}

func TestUserPrompt_NoSessionNoop(t *testing.T) {
	// Passing nil session should not panic or error
	err := HandleUserPrompt(nil)
	if err != nil {
		t.Errorf("expected no error for nil session, got: %v", err)
	}
}

func TestUserPrompt_TurnScopedClearsSecretSince(t *testing.T) {
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkSecretSessionWithScope("turn")

	if state.SecretSessionSince.IsZero() {
		t.Fatal("SecretSessionSince should be set after marking")
	}

	_ = HandleUserPrompt(state)

	// After turn-scoped clear, the since timestamp should be zero
	if !state.SecretSessionSince.IsZero() {
		t.Error("SecretSessionSince should be zeroed after turn-scoped clear")
	}
}

func TestUserPrompt_MaybeAdvanceTurnTimeGap(t *testing.T) {
	// This tests the time-gap based turn detection used in production
	// (MaybeAdvanceTurn). HandleUserPrompt uses IncrementTurn directly,
	// but we should verify MaybeAdvanceTurn also works.
	projectRoot := t.TempDir()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	state := session.NewState(projectRoot)
	state.MarkSecretSessionWithScope("turn")

	now := time.Now()

	// First tool call
	state.MaybeAdvanceTurn(now)
	if state.TurnCounter != 0 {
		t.Fatalf("first call should not advance turn, got %d", state.TurnCounter)
	}

	// Second tool call within threshold — should NOT advance
	secondCall := now.Add(5 * time.Second)
	state.MaybeAdvanceTurn(secondCall)
	if state.TurnCounter != 0 {
		t.Fatalf("call within threshold should not advance turn, got %d", state.TurnCounter)
	}

	// Third tool call after threshold from the LAST call — SHOULD advance and clear turn-scoped secret
	state.MaybeAdvanceTurn(secondCall.Add(session.TurnGapThreshold + time.Second))
	if state.TurnCounter != 1 {
		t.Fatalf("call after threshold should advance turn, got %d", state.TurnCounter)
	}
	if state.SecretSession {
		t.Error("turn-scoped secret should be cleared after turn gap threshold")
	}
}
