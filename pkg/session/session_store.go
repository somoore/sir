package session

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/policy"
)

// Update is the blessed session-mutation helper for all callers that
// need to read the current session, mutate it, and save the result.
// It acquires the session file lock, loads the current state (falling
// back to a fresh State only when the file does not yet exist — any
// other load error is returned as-is so callers fail closed), passes
// the state to the mutation function, and saves the result under the
// same lock. Fresh sessions are also saved so the file exists on
// disk for subsequent readers.
func Update(projectRoot string, fn func(*State) error) error {
	return WithSessionLock(projectRoot, func() error {
		state, err := Load(projectRoot)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("load session for update: %w", err)
			}
			state = NewState(projectRoot)
		}
		if err := fn(state); err != nil {
			return err
		}
		return state.Save()
	})
}

// Snapshot is a value-type copy of the racy session fields. It is returned by
// State.Snapshot() under the read lock so that callers reading multiple fields
// see a self-consistent view without acquiring the mutex themselves.
type Snapshot struct {
	SecretSession      bool
	TurnCounter        int
	ApprovalScope      policy.ApprovalScope
	SecretApprovalTurn int
}

// Snapshot returns a self-consistent value-type copy of the secret/turn fields.
func (s *State) Snapshot() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return Snapshot{
		SecretSession:      s.SecretSession,
		TurnCounter:        s.TurnCounter,
		ApprovalScope:      s.ApprovalScope,
		SecretApprovalTurn: s.SecretApprovalTurn,
	}
}
