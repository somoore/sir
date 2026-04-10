package hooks

import (
	"os"
	"testing"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// SubagentPolicy evaluates whether agent delegation should be allowed.
// This is the classification logic from evaluate.go extracted for testability.
type SubagentPolicy struct {
	AllowDelegation bool
	SecretSession   bool
	DenyAll         bool
	ElevatedPosture bool // true if session has posture changes pending
	DangerousTools  []string
}

// EvaluateSubagentDelegation returns a decision for an Agent tool call.
func EvaluateSubagentDelegation(policy SubagentPolicy) *core.Response {
	if policy.DenyAll {
		return &core.Response{Decision: "deny", Reason: "session in deny-all mode"}
	}

	if !policy.AllowDelegation {
		return &core.Response{Decision: "deny", Reason: "delegation disabled by lease"}
	}

	if policy.SecretSession {
		// Check if delegated tools include dangerous ones (network, bash, write)
		for _, tool := range policy.DangerousTools {
			switch tool {
			case "Bash", "Write", "WebFetch", "WebSearch":
				return &core.Response{
					Decision: "ask",
					Reason:   "secret session + dangerous tools in delegation",
				}
			}
		}
		// Read-only tools are safe even in secret session
		return &core.Response{Decision: "allow", Reason: "delegation with safe tools only"}
	}

	if policy.ElevatedPosture {
		return &core.Response{
			Decision: "ask",
			Reason:   "delegation during elevated posture state",
		}
	}

	return &core.Response{Decision: "allow", Reason: "clean session, delegation allowed"}
}

// --- Tests ---

func TestSubagent_DelegationDisabled(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: false,
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny when delegation disabled, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSubagent_SecretSessionDangerousTools(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: true,
		SecretSession:   true,
		DangerousTools:  []string{"Read", "Bash", "Grep"},
	})
	if resp.Decision != "ask" {
		t.Errorf("expected ask for secret session + Bash, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSubagent_SecretSessionSafeTools(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: true,
		SecretSession:   true,
		DangerousTools:  []string{"Read", "Grep", "Glob"},
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow for secret session + safe tools only, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSubagent_ElevatedPosture(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: true,
		ElevatedPosture: true,
	})
	if resp.Decision != "ask" {
		t.Errorf("expected ask for elevated posture, got %s: %s", resp.Decision, resp.Reason)
	}
}

func TestSubagent_NormalSession(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: true,
	})
	if resp.Decision != "allow" {
		t.Errorf("expected allow for clean session, got %s: %s", resp.Decision, resp.Reason)
	}
}

// TestSubagent_DenyAllOverridesEverything verifies that deny-all takes precedence.
func TestSubagent_DenyAllOverridesEverything(t *testing.T) {
	resp := EvaluateSubagentDelegation(SubagentPolicy{
		AllowDelegation: true,
		DenyAll:         true,
	})
	if resp.Decision != "deny" {
		t.Errorf("expected deny for deny-all session, got %s: %s", resp.Decision, resp.Reason)
	}
}

// TestSubagent_IntegrationWithEvaluatePayload tests that Agent tool calls go through
// the main evaluation pipeline correctly.
func TestSubagent_IntegrationWithEvaluatePayload(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)
	state := session.NewState(projectRoot)
	state.Save() // populate SessionHash

	// Mark session as secret
	state.MarkSecretSession()
	state.Save() // update hash after mutation

	payload := &HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "refactor the codebase"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}

	// Agent delegation during secret session must be denied — matches
	// mister-core/src/policy.rs::test_delegate_secret_session_denied. The Go
	// layer must never be more permissive than Rust. See parity_test.go.
	if resp.Decision != "deny" {
		t.Errorf("Agent delegation during secret session: expected deny, got %s (reason: %s)",
			resp.Decision, resp.Reason)
	}
}

// TestSubagent_CleanSessionAllowed verifies that Agent tool calls go through
// when session is clean.
func TestSubagent_CleanSessionAllowed(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)
	state := session.NewState(projectRoot)
	state.Save() // populate SessionHash

	payload := &HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "refactor the codebase"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}

	// Clean session = delegation allowed
	if resp.Decision != "allow" {
		t.Errorf("Agent delegation during clean session: expected allow, got %s (reason: %s)",
			resp.Decision, resp.Reason)
	}
}
