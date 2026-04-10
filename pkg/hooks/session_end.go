// Package hooks — session_end.go handles the SessionEnd hook event.
// Fires when the Claude Code session is terminating. sir finalizes the session
// by writing a closing ledger entry with final stats and cleaning up ephemeral state.
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

// runSessionTerminalPostureSweep re-hashes every posture file one last
// time at the end of a session (or at the end of a turn that terminates
// the session, in Codex's case) and appends a `posture_change` alert to
// the ledger for any drift. After alerting, the stored posture hashes
// are refreshed so a subsequent sweep (e.g. the same session fires both
// Stop and SessionEnd) does not double-alert on the same drift.
//
// This function is the backstop for the Codex single-turn `apply_patch`
// blind spot summarized in docs/research/validation-summary.md. Codex-cli 0.118
// does not fire PreToolUse for apply_patch, and a one-shot `codex exec`
// has no following PostToolUse for the existing sentinel re-hash to run
// in — so drift is invisible until this sweep catches it at session end.
// It also hardens the Claude Code and Gemini paths against any similar
// single-turn edge cases.
func runSessionTerminalPostureSweep(projectRoot string) error {
	return session.WithSessionLock(projectRoot, func() error {
		st, err := loadOptionalLifecycleSession(projectRoot, "session-terminal posture sweep")
		if err != nil {
			return err
		}
		if st == nil {
			return nil // no session — nothing to compare against
		}
		l, err := loadLifecycleLease(projectRoot, "session-terminal posture sweep")
		if err != nil {
			return err
		}
		drifted := CheckPostureIntegrity(projectRoot, st, l)
		for _, f := range drifted {
			alert := &ledger.Entry{
				ToolName:  "sir-hook",
				Verb:      "posture_change",
				Target:    f,
				Decision:  "alert",
				Reason:    "posture file modified — detected at session-terminal sweep (closes single-turn apply_patch blind spot)",
				Severity:  "MEDIUM",
				AlertType: "posture_change_session_end",
			}
			if logErr := ledger.Append(projectRoot, alert); logErr != nil {
				fmt.Fprintf(os.Stderr, "sir: session-terminal posture alert append: %v\n", logErr)
			}
		}
		// Refresh stored hashes so a subsequent sweep in the same
		// session (Stop fires, then later SessionEnd fires) does not
		// re-alert on already-recorded drift.
		if len(drifted) > 0 {
			st.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
			return st.Save()
		}
		return nil
	})
}

// SessionEndPayload is the JSON structure received from Claude Code for SessionEnd.
type SessionEndPayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
}

// EvaluateSessionEnd is the SessionEnd hook handler.
// It finalizes the session in the ledger and cleans up ephemeral state.
//
// Session-end sentinel sweep (single-turn blind-spot closure):
// Before writing the closing stats, sir re-hashes every posture file
// one last time and compares against the session-start hashes. Any
// drift gets a `posture_change` ledger alert. This closes a Codex-
// specific gap where `apply_patch` bypasses PreToolUse and a one-shot
// `codex exec` session has no subsequent PostToolUse to catch the
// write post-hoc. The sweep runs for
// all agents (not just Codex) — extra belt-and-suspenders for the
// Claude Code / Gemini single-turn paths at effectively zero cost.
func EvaluateSessionEnd(projectRoot string, ag agent.Agent) error {
	_ = ag // accepted for API symmetry; SessionEnd has no stdout response
	// Read stdin
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload SessionEndPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Final posture sweep: re-hash sentinel files and alert on any
	// drift that was not caught during the session. This is the only
	// backstop for Codex `apply_patch` posture writes in single-turn
	// `codex exec` invocations — there is no next PostToolUse in that
	// flow, so the existing post-hoc re-hash never fires. Runs in both
	// EvaluateSessionSummary (Stop) and here; whichever fires first
	// alerts and refreshes the stored hash, the second is a no-op.
	if err := runSessionTerminalPostureSweep(projectRoot); err != nil {
		return fmt.Errorf("session-terminal posture sweep: %w", err)
	}

	// Read ledger for final stats (AFTER the sweep so alerts are counted).
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		entries = nil // Proceed without stats if ledger can't be read
	}
	stats := computeSessionStats(entries, sessionStartFloor(projectRoot))

	// Write closing ledger entry
	closingReason := fmt.Sprintf(
		"session ended: %d total decisions, %d allowed, %d asked, %d blocked, %d alerts",
		stats.TotalEntries, stats.Allowed, stats.Asked, stats.Blocked, stats.Alerts,
	)

	entry := &ledger.Entry{
		ToolName: "sir-hook",
		Verb:     "session_end",
		Target:   "session",
		Decision: "allow",
		Reason:   closingReason,
	}
	if logErr := ledger.Append(projectRoot, entry); logErr != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
	}

	// Finalize session state
	lockErr := session.WithSessionLock(projectRoot, func() error {
		state, err := loadOptionalLifecycleSession(projectRoot, "session-end")
		if err != nil {
			return err
		}
		if state == nil {
			// No session — nothing to finalize.
			return nil
		}

		// Clear ephemeral state (pending installs, turn-advanced flag)
		state.ClearPendingInstall()
		state.TurnAdvancedByHook = false

		return state.Save()
	})
	if lockErr != nil {
		// Log but don't fail — the session is ending anyway
		fmt.Fprintf(os.Stderr, "sir: session-end cleanup error: %v\n", lockErr)
	}

	return nil
}
