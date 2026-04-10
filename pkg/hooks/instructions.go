// Package hooks — instructions.go handles the InstructionsLoaded hook event.
// Fires when the host agent loads instruction files (CLAUDE.md,
// GEMINI.md, AGENTS.md, .cursorrules, etc.). Claude Code is the only
// agent with a native InstructionsLoaded event today; Gemini CLI and
// Codex do not expose this lifecycle event, so instruction tamper
// detection is Claude-Code-only until those agents add equivalent
// hooks. sir hashes the instruction content for tamper detection and
// logs provenance to the ledger. Instruction content is NEVER stored.
package hooks

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// InstructionsPayload is the JSON structure received from Claude Code for InstructionsLoaded.
type InstructionsPayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	FilePath      string `json:"file_path,omitempty"`
	Content       string `json:"content,omitempty"`
	Source        string `json:"source,omitempty"` // "repo", "user", "project", etc.
}

// EvaluateInstructionsLoaded is the InstructionsLoaded hook handler.
// It hashes instruction file content for tamper detection and determines provenance.
// Content is NEVER stored in the ledger or session state.
func EvaluateInstructionsLoaded(projectRoot string, ag agent.Agent) error {
	_ = ag // accepted for API symmetry; InstructionsLoaded has no stdout response
	// Read stdin
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload InstructionsPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Hash the content (never store the content itself)
	var contentHash string
	if payload.Content != "" {
		h := sha256.Sum256([]byte(payload.Content))
		contentHash = fmt.Sprintf("%x", h)
	}

	// Determine provenance
	provenance := determineInstructionProvenance(payload.FilePath, payload.Source, projectRoot)

	// Store hash in session state for tamper detection
	if contentHash != "" && payload.FilePath != "" {
		lockErr := session.WithSessionLock(projectRoot, func() error {
			state, err := loadOptionalLifecycleSession(projectRoot, "instructions-loaded")
			if err != nil {
				return err
			}
			if state == nil {
				// No session — nothing to do.
				return nil
			}
			if state.InstructionHashes == nil {
				state.InstructionHashes = make(map[string]string)
			}
			// Use relative path as key for consistency
			key := payload.FilePath
			if rel, err := filepath.Rel(projectRoot, payload.FilePath); err == nil {
				key = rel
			}
			state.InstructionHashes[key] = contentHash
			return state.Save()
		})
		if lockErr != nil {
			return fmt.Errorf("instructions-loaded: %w", lockErr)
		}
	}

	// Log to ledger (content hash only, never content)
	entry := &ledger.Entry{
		ToolName:    "sir-hook",
		Verb:        "instructions_loaded",
		Target:      payload.FilePath,
		Provenance:  provenance,
		Decision:    "allow",
		Reason:      fmt.Sprintf("instruction file loaded (source: %s)", provenance),
		ContentHash: contentHash,
	}
	if logErr := ledger.Append(projectRoot, entry); logErr != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
	}

	return nil
}

// determineInstructionProvenance classifies the instruction file source.
func determineInstructionProvenance(filePath, source, projectRoot string) string {
	// If source is explicitly provided, use it
	if source != "" {
		return source
	}

	if filePath == "" {
		return "unknown"
	}

	// Check if file is within the project (repo-local)
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return "unknown"
	}
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		return "unknown"
	}

	if strings.HasPrefix(absPath, absRoot+string(filepath.Separator)) {
		return "repo"
	}

	// Check if it's a user-level file (under home directory)
	home, err := os.UserHomeDir()
	if err == nil {
		if strings.HasPrefix(absPath, home+string(filepath.Separator)) {
			return "user"
		}
	}

	return "external"
}
