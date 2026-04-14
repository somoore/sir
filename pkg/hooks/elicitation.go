// Package hooks — elicitation.go handles the Elicitation hook event.
// Elicitation is when Claude Code asks the user a question (e.g., "What is your API key?").
// sir intercepts these to detect credential harvesting attempts.
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// ElicitationPayload is the JSON structure for an elicitation hook event.
type ElicitationPayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	Message       string `json:"message"`
	ToolUseID     string `json:"tool_use_id"`
	CWD           string `json:"cwd"`
}

// harvestingPatterns are substrings in elicitation messages that suggest
// the model is trying to harvest credentials from the developer.
var harvestingPatterns = []string{
	"api key",
	"api_key",
	"apikey",
	"secret key",
	"secret_key",
	"access token",
	"access_token",
	"auth token",
	"auth_token",
	"password",
	"credential",
	"private key",
	"private_key",
	"ssh key",
	"bearer token",
	"database url",
	"database_url",
	"connection string",
	"aws_secret",
	"aws_access",
	".env",
}

// EvaluateElicitation is the Elicitation hook handler.
// It reads an elicitation payload from stdin, scans for credential harvesting,
// and warns on stderr if suspicious patterns are found.
func EvaluateElicitation(projectRoot string, ag agent.Agent) error {
	_ = ag // accepted for API symmetry; Elicitation writes to stderr only
	// Read stdin with size limit
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}

	var payload ElicitationPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal elicitation payload: %w", err)
	}

	// Scan message for credential harvesting patterns
	matched := scanForHarvesting(payload.Message)
	if len(matched) == 0 {
		// No suspicious patterns — allow silently
		return nil
	}

	// Raise posture under the session lock. Elicitation hooks can
	// fire concurrently with a PreToolUse/PostToolUse handler on the
	// same project, so a raw Load→mutate→Save would race. Missing
	// sessions are bootstrapped; unreadable state is a hard failure.
	lockErr := session.WithSessionLock(projectRoot, func() error {
		l, leaseMeta, err := loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, err := loadOrCreateSession(projectRoot, l, leaseMeta)
		if err != nil {
			return fmt.Errorf("load session: %w", err)
		}
		state.RaisePosture(policy.PostureStateElevated)
		return state.Save()
	})
	if lockErr != nil {
		return fmt.Errorf("elicitation posture update: %w", lockErr)
	}

	// Log to ledger
	entry := &ledger.Entry{
		ToolName:  "Elicitation",
		Verb:      string(policy.VerbElicitationHarvest),
		Target:    truncateForLedger(payload.Message),
		Decision:  "alert",
		Reason:    fmt.Sprintf("credential harvesting patterns: %v", matched),
		Severity:  "MEDIUM",
		AlertType: "elicitation_harvesting",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}

	// Warn on stderr
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintln(os.Stderr, FormatElicitationWarning(matched))

	return nil
}

// scanForHarvesting checks an elicitation message for credential harvesting patterns.
// Returns the list of matched pattern names.
func scanForHarvesting(message string) []string {
	if message == "" {
		return nil
	}
	lower := strings.ToLower(message)
	var matched []string
	for _, pat := range harvestingPatterns {
		if strings.Contains(lower, pat) {
			matched = append(matched, pat)
		}
	}
	return matched
}

// truncateForLedger truncates a message for safe ledger storage.
// Never stores more than 80 chars. Replaces newlines with spaces.
func truncateForLedger(msg string) string {
	s := strings.ReplaceAll(msg, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 80 {
		return s[:77] + "..."
	}
	return s
}
