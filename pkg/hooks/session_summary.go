// Package hooks — session_summary.go handles the Stop hook event.
// Fires at turn end for all three supported host agents (Claude Code
// Stop, Gemini CLI AfterAgent, Codex Stop — all normalised to "Stop"
// by the adapters in pkg/agent). sir reads the ledger entries for
// the current session, computes summary statistics, writes a summary
// entry to the ledger, AND runs the session-terminal posture sweep
// that closes the Codex single-turn apply_patch blind spot (see
// runSessionTerminalPostureSweep in session_end.go for details).
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// StopPayload is the JSON structure received from Claude Code for the Stop event.
type StopPayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	Reason        string `json:"reason,omitempty"` // e.g., "end_turn", "max_tokens", etc.
}

// SessionStats holds summary statistics for a session's ledger entries.
type SessionStats struct {
	TotalEntries int `json:"total_entries"`
	Allowed      int `json:"allowed"`
	Asked        int `json:"asked"`
	Blocked      int `json:"blocked"`
	Alerts       int `json:"alerts"`
}

// EvaluateSessionSummary is the Stop hook handler.
// It reads ledger entries, computes summary statistics, and writes
// a summary entry to the ledger.
func EvaluateSessionSummary(projectRoot string, ag agent.Agent) error {
	_ = ag // accepted for API symmetry; Stop summary writes to stderr only
	// Read stdin
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload StopPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Terminal posture sweep. For Codex this is the ONLY place the
	// sweep runs — Codex does not fire SessionEnd, only Stop → here.
	// Without this call, a one-shot `codex exec` that used apply_patch
	// to modify a posture file would go unalerted. Must run BEFORE the session_summary
	// stats are computed so the new posture_change alerts are counted.
	if err := runSessionTerminalPostureSweep(projectRoot); err != nil {
		return fmt.Errorf("session-summary posture sweep: %w", err)
	}

	// Read all ledger entries
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		// Cannot read ledger — log to stderr and exit gracefully
		fmt.Fprintf(os.Stderr, "sir: cannot read ledger for summary: %v\n", err)
		return nil
	}

	startedAt, err := sessionStartFloor(projectRoot, "session-summary")
	if err != nil {
		return err
	}
	stats := computeSessionStats(entries, startedAt)

	// Write summary entry to ledger
	summaryReason := fmt.Sprintf(
		"session summary: %d total, %d allowed, %d asked, %d blocked, %d alerts",
		stats.TotalEntries, stats.Allowed, stats.Asked, stats.Blocked, stats.Alerts,
	)

	entry := &ledger.Entry{
		ToolName: "sir-hook",
		Verb:     "session_summary",
		Target:   payload.Reason,
		Decision: "allow",
		Reason:   summaryReason,
	}
	if logErr := ledger.Append(projectRoot, entry); logErr != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
	}

	// Print summary to stderr so it appears in Claude Code context
	if stats.Blocked > 0 || stats.Alerts > 0 {
		fmt.Fprintf(os.Stderr, "sir: session had %d blocked action(s) and %d alert(s). Run 'sir explain --last' for details.\n",
			stats.Blocked, stats.Alerts)
	}

	// Load session and check if it needs attention
	state, sErr := session.Load(projectRoot)
	if sErr == nil && state.SecretSession {
		fmt.Fprintf(os.Stderr, "sir: session still carries secret labels. Run 'sir unlock' if no longer needed.\n")
	}

	return nil
}

// computeSessionStats counts decisions across ledger entries whose
// timestamp is at or after `since`. If `since` is the zero time, every
// entry is counted — preserves the legacy behaviour for callers that do
// not care about session scoping.
//
// Scoping matters because the validation findings in
// docs/research/validation-summary.md observed the
// session-summary line ("sir: session had N blocked action(s)") carrying
// stale cumulative counts from previous sessions in the same project —
// e.g., a block from an earlier run leaking into every subsequent
// headless `gemini -p` invocation.
func computeSessionStats(entries []ledger.Entry, since time.Time) SessionStats {
	var stats SessionStats
	for _, e := range entries {
		if !since.IsZero() && e.Timestamp.Before(since) {
			continue
		}
		stats.TotalEntries++
		switch e.Decision {
		case "allow":
			stats.Allowed++
		case "ask":
			stats.Asked++
		case "deny":
			stats.Blocked++
		case "alert":
			stats.Alerts++
		}
	}
	return stats
}

// sessionStartFloor returns the StartedAt of the currently persisted
// session, or the zero time if session state cannot be loaded. The zero
// time is a safe fallback: computeSessionStats treats it as "no filter"
// and reverts to whole-ledger counting, which is the legacy behaviour.
func sessionStartFloor(projectRoot, hookName string) (time.Time, error) {
	state, err := loadOptionalLifecycleSession(projectRoot, hookName)
	if err != nil {
		return time.Time{}, err
	}
	if state == nil {
		return time.Time{}, nil
	}
	return state.StartedAt, nil
}
