package session

import (
	"time"

	"github.com/somoore/sir/pkg/policy"
)

// MarkSecretSession flags the session as carrying secret-labeled data.
// Defaults to "turn" scope so the secret flag clears when the next turn begins.
func (s *State) MarkSecretSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SecretSession = true
	if s.SecretSessionSince.IsZero() {
		s.SecretSessionSince = time.Now()
	}
	if s.ApprovalScope == "" {
		s.ApprovalScope = policy.ApprovalScopeTurn
	}
	s.SecretApprovalTurn = s.TurnCounter
}

// MarkSecretSessionWithScope flags the session as secret with the given scope.
func (s *State) MarkSecretSessionWithScope(scope policy.ApprovalScope) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.SecretSession = true
	if s.SecretSessionSince.IsZero() {
		s.SecretSessionSince = time.Now()
	}
	if s.ApprovalScope == "" {
		s.ApprovalScope = policy.ApprovalScopeTurn
	}
	s.SecretApprovalTurn = s.TurnCounter
	if scope == policy.ApprovalScopeTurn || scope == policy.ApprovalScopeSession {
		s.ApprovalScope = scope
	}
}

// MaybeAdvanceTurn detects turn boundaries using a time gap heuristic and advances
// the turn counter when a new turn is detected. If the secret flag has turn scope
// and the turn has advanced past the approval turn, the secret flag is cleared.
func (s *State) MaybeAdvanceTurn(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.TurnAdvancedByHook {
		s.TurnAdvancedByHook = false
		s.LastToolCallAt = now
		return
	}
	if !s.LastToolCallAt.IsZero() && now.Sub(s.LastToolCallAt) >= TurnGapThreshold {
		s.TurnCounter++
		s.clearTurnEvidenceLocked()
		if s.SecretSession && s.ApprovalScope == policy.ApprovalScopeTurn && s.TurnCounter > s.SecretApprovalTurn {
			s.clearSecretSessionLocked()
		}
	}
	s.LastToolCallAt = now
}

// AdvanceTurnByHook advances the turn counter and sets TurnAdvancedByHook so that
// the next MaybeAdvanceTurn call (in PreToolUse) skips the time-gap heuristic.
func (s *State) AdvanceTurnByHook() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TurnCounter++
	s.TurnAdvancedByHook = true
	s.clearTurnEvidenceLocked()
	if s.SecretSession && s.ApprovalScope == policy.ApprovalScopeTurn && s.TurnCounter > s.SecretApprovalTurn {
		s.clearSecretSessionLocked()
	}
}

// IncrementTurn unconditionally advances the turn counter and clears turn-scoped secrets.
func (s *State) IncrementTurn() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TurnCounter++
	s.clearTurnEvidenceLocked()
	if s.SecretSession && s.ApprovalScope == policy.ApprovalScopeTurn && s.TurnCounter > s.SecretApprovalTurn {
		s.clearSecretSessionLocked()
	}
}

// ClearSecretSession clears the secret session flag.
func (s *State) ClearSecretSession() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearSecretSessionLocked()
}

// clearSecretSessionLocked clears the secret flag. Caller must hold s.mu.
func (s *State) clearSecretSessionLocked() {
	s.SecretSession = false
	s.SecretSessionSince = time.Time{}
	s.ApprovalScope = ""
	s.SecretApprovalTurn = 0
}
