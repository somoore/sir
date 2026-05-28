// Package ledger implements an append-only hash-chained ledger for sir.
// The ledger stores paths, labels, hashes, verdicts, timestamps, and optional
// redacted investigation evidence. Raw secrets are never persisted.
package ledger

import (
	"path/filepath"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// Entry is a single ledger entry.
type Entry struct {
	Index       int       `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	PrevHash    string    `json:"prev_hash"`
	EntryHash   string    `json:"entry_hash"`
	HashVersion int       `json:"hash_version,omitempty"`

	// Tool call context
	ToolName string `json:"tool_name"`
	Verb     string `json:"verb"`
	Target   string `json:"target"`

	// Labels assigned
	Sensitivity string `json:"sensitivity,omitempty"`
	Trust       string `json:"trust,omitempty"`
	Provenance  string `json:"provenance,omitempty"`

	// Verdict
	Decision string `json:"decision"` // allow, deny, ask
	Reason   string `json:"reason"`

	// Optional metadata
	ContentHash string `json:"content_hash,omitempty"` // SHA-256 of content, never content itself
	Preview     string `json:"preview,omitempty"`      // first 80 chars, redacted if secret
	Severity    string `json:"severity,omitempty"`     // HIGH, MEDIUM, LOW
	AlertType   string `json:"alert_type,omitempty"`   // sentinel_mutation, posture_tamper, etc.
	DetectionID string `json:"detection_id,omitempty"` // stable behavior-detection ID (pkg/detect)
	// DetectionRoute is the computed escalation route (silent/local/siem/slack)
	// for this entry's detection, including dynamic promotion (suspicion,
	// repetition). It is transient: not persisted and not hashed, set at stamp
	// time and consumed by the same-process telemetry/Slack emit.
	DetectionRoute string `json:"-"`
	Evidence       string `json:"evidence,omitempty"`     // optional redacted investigation evidence
	Agent          string `json:"agent,omitempty"`        // target agent id for tamper alerts
	DiffSummary    string `json:"diff_summary,omitempty"` // concise diff summary for posture alerts
	Restored       bool   `json:"restored,omitempty"`     // whether auto-restore succeeded
	LatencyMs      int    `json:"latency_ms,omitempty"`   // sir decision latency in ms (perf metric)
}

const (
	legacyHashVersion  = 1
	currentHashVersion = 4
)

// LedgerPath returns the path to the ledger file for a project.
func LedgerPath(projectRoot string) string {
	return filepath.Join(session.StateDir(projectRoot), "ledger.jsonl")
}
