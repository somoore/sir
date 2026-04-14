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
	hookslifecycle "github.com/somoore/sir/pkg/hooks/lifecycle"
	hookmessages "github.com/somoore/sir/pkg/hooks/messages"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// runSessionTerminalPostureSweep re-hashes every posture file one last
// time at the end of a session (or at the end of a turn that terminates
// the session, in Codex's case). Ordinary posture drift still gets the
// existing `posture_change` alert + rebaseline behavior. Hook-config drift
// is routed through the same restore/fail-closed path the live hook pipeline
// uses so a last-turn tamper cannot be blessed by a session-end rebaseline.
//
// This function is the backstop for the Codex single-turn `apply_patch`
// blind spot summarized in docs/research/validation-summary.md. Codex-cli 0.118
// does not fire PreToolUse for apply_patch, and a one-shot `codex exec`
// has no following PostToolUse for the existing sentinel re-hash to run
// in — so drift is invisible until this sweep catches it at session end.
// It also hardens the Claude Code and Gemini paths against any similar
// single-turn edge cases.
func runSessionTerminalPostureSweep(projectRoot string, ag agent.Agent) error {
	return session.WithSessionLock(projectRoot, func() error {
		st, err := loadOptionalLifecycleSession(projectRoot, "session-terminal posture sweep")
		if err != nil {
			return err
		}
		if st == nil {
			return nil // no session — nothing to compare against
		}
		l, leaseMeta, err := loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("session-terminal posture sweep: load lease: %w", err)
		}
		if err := syncSessionLeaseHashAfterSirRefresh(st, leaseMeta); err != nil {
			return fmt.Errorf("session-terminal posture sweep: sync refreshed lease hash into session: %w", err)
		}

		drift := hookslifecycle.DetectPostureIntegrityDrift(projectRoot, st, l)
		if len(drift.NonHookFiles) == 0 && len(drift.HookFiles) == 0 {
			return nil
		}

		if len(drift.HookFiles) > 0 {
			restoredHooks := handleSessionTerminalHookTamper(projectRoot, st, drift.HookFiles, ag)
			if len(restoredHooks) > 0 {
				currentHashes := HashSentinelFiles(projectRoot, restoredHooks)
				if st.PostureHashes == nil {
					st.PostureHashes = make(map[string]string, len(l.PostureFiles))
				}
				for relPath, hash := range currentHashes {
					st.PostureHashes[relPath] = hash
				}
			}
		}

		if len(drift.NonHookFiles) > 0 {
			currentHashes := HashSentinelFiles(projectRoot, drift.NonHookFiles)
			for _, f := range drift.NonHookFiles {
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
				if stateHash, ok := currentHashes[f]; ok {
					if st.PostureHashes == nil {
						st.PostureHashes = make(map[string]string, len(l.PostureFiles))
					}
					st.PostureHashes[f] = stateHash
				}
			}
		}

		return st.Save()
	})
}

func handleSessionTerminalHookTamper(projectRoot string, state *session.State, hookFiles []AgentHookFile, ag agent.Agent) []string {
	target := FormatChangedHookTargets(hookFiles)
	restoredPaths := make([]string, 0, len(hookFiles))
	for _, hookFile := range hookFiles {
		diffSummary := managedHookDiffSummary(hookFile)
		restored := AutoRestoreAgentHookFile(hookFile)
		entry, err := appendHookTamperEntry(
			projectRoot,
			"sir-hook",
			hookFile,
			"deny",
			"security configuration was modified unexpectedly - all tool calls blocked",
			restored,
			diffSummary,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		}
		if entry != nil {
			emitTelemetryEvent(entry, state, ag)
		}
		if restored {
			restoredPaths = append(restoredPaths, hookFile.RelativePath)
			fmt.Fprintln(os.Stderr, hookmessages.FormatPostureRestore(hookFile.DisplayPath))
		}
	}
	state.SetDenyAll(fmt.Sprintf("posture file tampered: %s", target))
	fmt.Fprintln(os.Stderr, hookmessages.FormatHookTamper(target))
	return restoredPaths
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
// Before writing the closing stats, sir re-checks posture drift one
// last time and routes hook-config drift through the live restore /
// deny-all path. Ordinary posture drift still gets the existing
// `posture_change` alert and rebaseline. This closes a Codex-specific
// gap where `apply_patch` bypasses PreToolUse and a one-shot
// `codex exec` session has no subsequent PostToolUse to catch the
// write post-hoc. The sweep runs for all agents (not just Codex) —
// extra belt-and-suspenders for the Claude Code / Gemini single-turn
// paths at effectively zero cost.
func EvaluateSessionEnd(projectRoot string, ag agent.Agent) error {
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

	// Final posture sweep: detect drift that was not caught during the
	// session. Hook-config drift is restored and fail-closed like the
	// live hook path; ordinary posture drift is still alerted and
	// rebaselined. This is the backstop for Codex `apply_patch`
	// posture writes in single-turn `codex exec` invocations — there is
	// no next PostToolUse in that flow, so the existing post-hoc
	// re-hash never fires. Runs in both EvaluateSessionSummary (Stop)
	// and here.
	if err := runSessionTerminalPostureSweep(projectRoot, ag); err != nil {
		return fmt.Errorf("session-terminal posture sweep: %w", err)
	}

	// Read ledger for final stats (AFTER the sweep so alerts are counted).
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		entries = nil // Proceed without stats if ledger can't be read
	}
	startedAt, err := sessionStartFloor(projectRoot, "session-end")
	if err != nil {
		return err
	}
	stats := computeSessionStats(entries, startedAt)

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
		return fmt.Errorf("session-end cleanup: %w", lockErr)
	}

	return nil
}
