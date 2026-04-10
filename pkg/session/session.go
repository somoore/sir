// Package session manages sir session state persistence.
// Session state tracks security-relevant flags across tool calls within a session.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/somoore/sir/pkg/policy"
)

// TurnGapThreshold is the minimum duration between tool calls that signals a new turn.
// Claude Code tool calls within a single response typically fire within milliseconds of each
// other. A gap longer than this threshold means the model finished responding and the user
// sent a new message — i.e., a new "turn".
const TurnGapThreshold = 30 * time.Second

// State holds the mutable session state for a sir session.
// All exported mutation methods are guarded by mu to prevent data races
// when Claude Code fires parallel tool calls.
type State struct {
	mu                    sync.RWMutex         `json:"-"`
	SchemaVersion         uint32               `json:"schema_version"`
	SessionID             string               `json:"session_id"`
	ProjectRoot           string               `json:"project_root"`
	StartedAt             time.Time            `json:"started_at"`
	SecretSession         bool                 `json:"secret_session"`
	SecretSessionSince    time.Time            `json:"secret_session_since,omitempty"`
	ApprovalScope         policy.ApprovalScope `json:"approval_scope,omitempty"` // "session" (default) or "turn"
	TurnCounter           int                  `json:"turn_counter"`
	SecretApprovalTurn    int                  `json:"secret_approval_turn,omitempty"` // turn when secret was approved
	LastToolCallAt        time.Time            `json:"last_tool_call_at,omitempty"`    // timestamp of most recent PreToolUse
	RecentlyReadUntrusted bool                 `json:"recently_read_untrusted"`
	PendingInstall        *PendingInstall      `json:"pending_install,omitempty"`
	PostureHashes         map[string]string    `json:"posture_hashes,omitempty"`
	DenyAll               bool                 `json:"deny_all"`
	DenyAllReason         string               `json:"deny_all_reason,omitempty"`
	LeaseHash             string               `json:"lease_hash,omitempty"`       // SHA-256 of lease.json at session start
	GlobalHookHash        string               `json:"global_hook_hash,omitempty"` // SHA-256 of the managed hook/config subtrees for all registered host agents at session start
	SessionHash           string               `json:"session_hash,omitempty"`     // SHA-256 of session.json content (excludes this field)

	// MCP defense fields
	Posture             policy.PostureState `json:"posture,omitempty"`               // "normal", "elevated", "critical"
	MCPInjectionSignals []string            `json:"mcp_injection_signals,omitempty"` // pattern names from injection scans
	TaintedMCPServers   []string            `json:"tainted_mcp_servers,omitempty"`   // MCP servers that returned injection signals

	// PendingInjectionAlert is set by PostToolUse when MCP response injection is
	// detected. The next PreToolUse checks this flag and returns "ask" before
	// processing the tool call, closing the one-action window.
	PendingInjectionAlert bool   `json:"pending_injection_alert,omitempty"`
	InjectionAlertDetail  string `json:"injection_alert_detail,omitempty"`

	// Hook expansion fields
	TurnAdvancedByHook bool              `json:"turn_advanced_by_hook,omitempty"` // true if UserPromptSubmit hook advanced the turn
	InstructionHashes  map[string]string `json:"instruction_hashes,omitempty"`    // SHA-256 of loaded instruction files

	// Artifact lineage fields
	ActiveEvidence     []LineageEvidence            `json:"active_evidence,omitempty"`
	DerivedFileLineage map[string]DerivedPathRecord `json:"derived_file_lineage,omitempty"`
}

// PendingInstall tracks an in-progress install command for sentinel pre/post comparison.
type PendingInstall struct {
	Command        string            `json:"command"`
	Manager        string            `json:"manager"`
	SentinelHashes map[string]string `json:"sentinel_hashes"`
	LockfileHash   string            `json:"lockfile_hash,omitempty"`
}

// VerifySessionIntegrity checks that session.json has not been modified outside
// of sir's Save() method. Returns true if the session is intact.
// An empty SessionHash fails the check (fail closed) — an attacker cannot bypass
// integrity verification by clearing the hash field.
func VerifySessionIntegrity(state *State) bool {
	if state.SessionHash == "" {
		return false // fail closed: empty hash = tampered or corrupted
	}
	storedHash := state.SessionHash

	state.mu.Lock()
	state.SessionHash = ""
	data, err := json.MarshalIndent(state, "", "  ")
	state.SessionHash = storedHash
	state.mu.Unlock()

	if err != nil {
		return false
	}
	h := sha256.Sum256(data)
	computed := hex.EncodeToString(h[:])
	return computed == storedHash
}

// NewState creates a new session state.
func NewState(projectRoot string) *State {
	return &State{
		SchemaVersion:      policy.SessionSchemaVersion,
		SessionID:          fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%d", projectRoot, time.Now().UnixNano()))))[:16],
		ProjectRoot:        projectRoot,
		StartedAt:          time.Now(),
		PostureHashes:      make(map[string]string),
		DerivedFileLineage: make(map[string]DerivedPathRecord),
	}
}
