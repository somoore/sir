// Package hooks — user_prompt.go handles the UserPromptSubmit hook event.
// Fires once per user message, before any tool calls. Advances the turn counter
// so turn-scoped secret approvals are cleared deterministically rather than
// relying on the time-gap heuristic.
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// UserPromptPayload is the JSON structure received from Claude Code for UserPromptSubmit.
type UserPromptPayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	// We do NOT inspect prompt content. Privacy by design.
}

// EvaluateUserPrompt is the UserPromptSubmit hook handler.
// It advances the turn counter, clearing turn-scoped secret approvals.
// The prompt content is never read or stored.
// UserPromptSubmit has no agent-specific output shape (no stdout response),
// but we accept the agent parameter for API symmetry and future-proofing.
func EvaluateUserPrompt(projectRoot string, ag agent.Agent) error {
	_ = ag // reserved for future use (e.g., Codex may emit a response)
	// Read stdin with size limit (payload is small but use standard pattern)
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload UserPromptPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Load session under lock, advance turn, save.
	lockErr := session.WithSessionLock(projectRoot, func() error {
		state, err := loadOptionalLifecycleSession(projectRoot, "user-prompt")
		if err != nil {
			return err
		}
		if state == nil {
			// No session — nothing to do. Not an error.
			return nil
		}

		// Advance turn deterministically via hook (skips time-gap heuristic)
		wasSecret := state.SecretSession
		state.AdvanceTurnByHook()

		// Log turn advancement to ledger if it cleared secrets
		if wasSecret && !state.SecretSession {
			entry := &ledger.Entry{
				ToolName: "sir-hook",
				Verb:     "turn_advance",
				Target:   "user_prompt",
				Decision: "allow",
				Reason:   "turn-scoped secret cleared on new user message",
			}
			if logErr := ledger.Append(projectRoot, entry); logErr != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
			}
		}

		return state.Save()
	})
	if lockErr != nil {
		return fmt.Errorf("user-prompt: %w", lockErr)
	}

	// UserPromptSubmit hooks should not produce stdout output.
	// Exit silently on success.
	return nil
}
