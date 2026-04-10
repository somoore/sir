package session

import (
	"testing"
	"time"

	"github.com/somoore/sir/pkg/policy"
)

// --- MarkSecretSession ---

func TestMarkSecretSession_SetsFlag(t *testing.T) {
	s := NewState("/p")
	if s.SecretSession {
		t.Fatal("precondition: SecretSession should be false")
	}
	s.MarkSecretSession()
	if !s.SecretSession {
		t.Fatal("SecretSession should be true after MarkSecretSession")
	}
}

func TestMarkSecretSession_SetsTimestamp(t *testing.T) {
	s := NewState("/p")
	before := time.Now()
	s.MarkSecretSession()
	after := time.Now()
	if s.SecretSessionSince.Before(before) || s.SecretSessionSince.After(after) {
		t.Fatalf("SecretSessionSince %v not between %v and %v", s.SecretSessionSince, before, after)
	}
}

func TestMarkSecretSession_TimestampIdempotent(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()
	first := s.SecretSessionSince
	time.Sleep(time.Millisecond) // ensure clock advances
	s.MarkSecretSession()
	if !s.SecretSessionSince.Equal(first) {
		t.Fatal("SecretSessionSince should not change on subsequent calls")
	}
}

func TestMarkSecretSession_DefaultsScopeToTurn(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()
	if s.ApprovalScope != policy.ApprovalScopeTurn {
		t.Fatalf("ApprovalScope = %q, want 'turn' (default)", s.ApprovalScope)
	}
}

func TestMarkSecretSession_RecordsApprovalTurn(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 5
	s.MarkSecretSession()
	if s.SecretApprovalTurn != 5 {
		t.Fatalf("SecretApprovalTurn = %d, want 5", s.SecretApprovalTurn)
	}
}

func TestMarkSecretSession_Idempotent(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()
	s.MarkSecretSession()
	s.MarkSecretSession()
	if !s.SecretSession {
		t.Fatal("SecretSession should remain true")
	}
}

func TestMarkSecretSession_UpdatesApprovalTurnOnSubsequentCalls(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 2
	s.MarkSecretSession()
	if s.SecretApprovalTurn != 2 {
		t.Fatalf("first call: SecretApprovalTurn = %d, want 2", s.SecretApprovalTurn)
	}
	s.TurnCounter = 7
	s.MarkSecretSession()
	// SecretApprovalTurn updates on every call (extends the approval)
	if s.SecretApprovalTurn != 7 {
		t.Fatalf("second call: SecretApprovalTurn = %d, want 7", s.SecretApprovalTurn)
	}
}

// --- MarkSecretSessionWithScope ---

func TestMarkSecretSessionWithScope_Turn(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 3
	s.MarkSecretSessionWithScope("turn")
	if !s.SecretSession {
		t.Fatal("SecretSession should be true")
	}
	if s.ApprovalScope != policy.ApprovalScopeTurn {
		t.Fatalf("ApprovalScope = %q, want 'turn'", s.ApprovalScope)
	}
	if s.SecretApprovalTurn != 3 {
		t.Fatalf("SecretApprovalTurn = %d, want 3", s.SecretApprovalTurn)
	}
}

func TestMarkSecretSessionWithScope_Session(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSessionWithScope("session")
	if s.ApprovalScope != policy.ApprovalScopeSession {
		t.Fatalf("ApprovalScope = %q, want 'session'", s.ApprovalScope)
	}
}

func TestMarkSecretSessionWithScope_InvalidScopeDefaultsToTurn(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSessionWithScope("invalid")
	// Invalid scope should fall back to default "turn"
	if s.ApprovalScope != policy.ApprovalScopeTurn {
		t.Fatalf("ApprovalScope = %q, want 'turn' (invalid scope should default to turn)", s.ApprovalScope)
	}
}

// --- ClearSecretSession ---

func TestClearSecretSession(t *testing.T) {
	s := NewState("/p")
	s.MarkSecretSession()
	s.ClearSecretSession()

	if s.SecretSession {
		t.Fatal("SecretSession should be false after clear")
	}
	if !s.SecretSessionSince.IsZero() {
		t.Fatal("SecretSessionSince should be zero after clear")
	}
	if s.ApprovalScope != "" {
		t.Fatalf("ApprovalScope should be empty after clear, got %q", s.ApprovalScope)
	}
	if s.SecretApprovalTurn != 0 {
		t.Fatalf("SecretApprovalTurn should be 0 after clear, got %d", s.SecretApprovalTurn)
	}
}

func TestClearSecretSession_OnNonSecretState(t *testing.T) {
	// Clearing when not set should be safe (no-op)
	s := NewState("/p")
	s.ClearSecretSession()
	if s.SecretSession {
		t.Fatal("should remain false")
	}
}

// --- IncrementTurn ---

func TestIncrementTurn_Advances(t *testing.T) {
	s := NewState("/p")
	if s.TurnCounter != 0 {
		t.Fatalf("initial TurnCounter = %d, want 0", s.TurnCounter)
	}
	s.IncrementTurn()
	if s.TurnCounter != 1 {
		t.Fatalf("after 1 increment: TurnCounter = %d, want 1", s.TurnCounter)
	}
	s.IncrementTurn()
	if s.TurnCounter != 2 {
		t.Fatalf("after 2 increments: TurnCounter = %d, want 2", s.TurnCounter)
	}
}

func TestIncrementTurn_ClearsTurnScopedSecret(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 5
	s.MarkSecretSessionWithScope("turn")
	// SecretApprovalTurn = 5, TurnCounter = 5
	// Incrementing should advance to 6 > 5, clearing the secret
	s.IncrementTurn()
	if s.SecretSession {
		t.Fatal("turn-scoped secret should be cleared when turn advances past approval turn")
	}
	if s.TurnCounter != 6 {
		t.Fatalf("TurnCounter = %d, want 6", s.TurnCounter)
	}
}

func TestIncrementTurn_DoesNotClearSessionScopedSecret(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 5
	s.MarkSecretSessionWithScope("session")
	s.IncrementTurn()
	if !s.SecretSession {
		t.Fatal("session-scoped secret should NOT be cleared on turn increment")
	}
}

func TestIncrementTurn_TurnScopedSecret_NotClearedOnSameTurn(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 0
	s.MarkSecretSessionWithScope("turn")
	// SecretApprovalTurn = 0, TurnCounter = 0
	// Increment to 1 > 0, should clear
	s.IncrementTurn()
	if s.SecretSession {
		t.Fatal("should be cleared: TurnCounter(1) > SecretApprovalTurn(0)")
	}
}

func TestIncrementTurn_TurnScopedSecret_MultipleIncrements(t *testing.T) {
	s := NewState("/p")
	s.TurnCounter = 3
	s.MarkSecretSessionWithScope("turn")
	// SecretApprovalTurn = 3
	// First increment: TurnCounter goes to 4 > 3, clears secret
	s.IncrementTurn()
	if s.SecretSession {
		t.Fatal("should be cleared after first increment past approval turn")
	}
	// Further increments should not break anything
	s.IncrementTurn()
	s.IncrementTurn()
	if s.TurnCounter != 6 {
		t.Fatalf("TurnCounter = %d, want 6", s.TurnCounter)
	}
	if s.SecretSession {
		t.Fatal("should remain cleared")
	}
}

func TestIncrementTurn_NoSecretSession_NoPanic(t *testing.T) {
	s := NewState("/p")
	// No secret set, increment should just work
	s.IncrementTurn()
	s.IncrementTurn()
	if s.TurnCounter != 2 {
		t.Fatalf("TurnCounter = %d, want 2", s.TurnCounter)
	}
}

// --- SetDenyAll ---
