// parity_test.go — Go-vs-Rust delegation parity.
//
// CLAUDE.md invariant:
//
//	"Sub-agents inherit parent's secret_session flag — secrets cannot be
//	laundered through delegation."
//
// mister-core/src/policy.rs returns Deny for the Delegate verb in a secret
// session (see test_delegate_secret_session_denied). The Go layer must never
// be more permissive than Rust. These tests lock that in for both entry
// points: the PreToolUse Agent path in evaluate.go and the SubagentStart path
// in subagent.go.
package hooks

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// TestDelegationParity_PreToolUse_SecretSession asserts that an Agent tool
// call during a secret session is denied by the Go PreToolUse path — matching
// mister-core's policy.rs::test_delegate_secret_session_denied. The Go layer
// must never be more permissive than Rust.
func TestDelegationParity_PreToolUse_SecretSession(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	state.MarkSecretSession()
	if err := state.Save(); err != nil {
		t.Fatalf("save secret session: %v", err)
	}

	payload := &HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "investigate repository"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}

	if resp.Decision != "deny" {
		t.Errorf("PreToolUse Agent + secret session: Go decision = %q, want %q (Rust returns deny; Go must never be more permissive). reason: %s",
			resp.Decision, "deny", resp.Reason)
	}
}

// TestDelegationParity_SubagentStart_SecretSession asserts that the
// SubagentStart hook denies delegation when the parent session has the
// secret flag set. The previous implementation returned ask, contradicting
// the CLAUDE.md delegation invariant and the Rust policy.
func TestDelegationParity_SubagentStart_SecretSession(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	// Persist lease so loadLease picks it up from the project state dir.
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	// Create a session in secret state and persist it.
	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	state.MarkSecretSession()
	if err := state.Save(); err != nil {
		t.Fatalf("save secret session: %v", err)
	}

	// Run the full SubagentStart path with the same stdin/stdout contract
	// used by the real hook, but drain stdout concurrently so the test
	// never deadlocks on a full pipe.
	buf, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
		HookEventName: "SubagentStart",
		AgentName:     "general-purpose",
		Tools:         []string{"Read", "Bash"},
	})
	if err != nil {
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	if len(buf) == 0 {
		t.Fatal("SubagentStart + secret session: expected a deny response, got no response (fail-open)")
	}

	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw: %s", err, string(buf))
	}

	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("SubagentStart + secret session: decision = %q, want %q (Rust returns deny; Go must never be more permissive). reason: %s",
			resp.HookSpecificOutput.PermissionDecision, "deny",
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestDelegationParity_PreToolUse_RiskySessionStates(t *testing.T) {
	cases := []struct {
		name            string
		mutate          func(*session.State)
		wantWarningText bool
	}{
		{
			name: "tainted mcp server",
			mutate: func(state *session.State) {
				state.AddTaintedMCPServer("jira")
			},
		},
		{
			name: "elevated posture",
			mutate: func(state *session.State) {
				state.RaisePosture(policy.PostureStateElevated)
			},
		},
		{
			name: "pending injection alert",
			mutate: func(state *session.State) {
				state.SetPendingInjectionAlert("pending injection alert")
			},
			wantWarningText: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			l := lease.DefaultLease()

			stateDir := session.StateDir(projectRoot)
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatalf("mkdir state: %v", err)
			}
			if err := l.Save(stateDir + "/lease.json"); err != nil {
				t.Fatalf("save lease: %v", err)
			}

			state := session.NewState(projectRoot)
			if err := state.Save(); err != nil {
				t.Fatalf("save initial session: %v", err)
			}
			tc.mutate(state)
			if err := state.Save(); err != nil {
				t.Fatalf("save mutated session: %v", err)
			}

			resp, err := evaluatePayload(&HookPayload{
				ToolName:  "Agent",
				ToolInput: map[string]interface{}{"task": "investigate repository"},
				CWD:       projectRoot,
			}, l, state, projectRoot)
			if err != nil {
				t.Fatalf("evaluatePayload: %v", err)
			}
			if resp.Decision == "allow" {
				t.Fatalf("Agent delegation after %s: expected blocked or gated decision, got allow (%s)", tc.name, resp.Reason)
			}
			if tc.wantWarningText {
				if resp.Decision != policy.VerdictAsk {
					t.Fatalf("Agent delegation after %s: expected ask with warning, got %q (%s)", tc.name, resp.Decision, resp.Reason)
				}
				if !strings.Contains(resp.Reason, "suspicious patterns") || !strings.Contains(resp.Reason, "pending injection alert") {
					t.Fatalf("Agent delegation after %s: expected suspicious-output warning in reason, got %q", tc.name, resp.Reason)
				}
			}
		})
	}
}

func TestDelegationParity_PreToolUse_LeaseDisallowsDelegationPreemptsRiskyAsk(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.AllowDelegation = false

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	state.AddTaintedMCPServer("jira")
	state.RaisePosture(policy.PostureStateCritical)
	if err := state.Save(); err != nil {
		t.Fatalf("save risky session: %v", err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "delegate work to a sub-agent"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != policy.VerdictDeny {
		t.Fatalf("Agent delegation with allow_delegation=false and risky state = %q, want %q (reason=%s)", resp.Decision, policy.VerdictDeny, resp.Reason)
	}
}

func TestDelegationParity_PreToolUse_LeaseDisallowPersistsTurnAdvance(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.AllowDelegation = false

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	before := time.Now().Add(-2 * session.TurnGapThreshold)
	state.LastToolCallAt = before
	if err := state.Save(); err != nil {
		t.Fatalf("save stale session: %v", err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "delegate work to a sub-agent"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != policy.VerdictDeny {
		t.Fatalf("Agent delegation with allow_delegation=false = %q, want %q (reason=%s)", resp.Decision, policy.VerdictDeny, resp.Reason)
	}

	loaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}
	if loaded.TurnCounter != 1 {
		t.Fatalf("TurnCounter = %d, want 1 after persisted turn advance", loaded.TurnCounter)
	}
	if !loaded.LastToolCallAt.After(before) {
		t.Fatalf("LastToolCallAt = %v, want persisted update after %v", loaded.LastToolCallAt, before)
	}
}

func TestDelegationParity_PreToolUse_RiskyStatePreservesSessionIntegrity(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	state.AddTaintedMCPServer("jira")
	if err := state.Save(); err != nil {
		t.Fatalf("save tainted session: %v", err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "investigate repository"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload risky delegation: %v", err)
	}
	if resp.Decision != policy.VerdictAsk {
		t.Fatalf("delegation decision = %q, want ask (reason=%s)", resp.Decision, resp.Reason)
	}
	if !session.VerifySessionIntegrity(state) {
		t.Fatal("delegation ask path should preserve session integrity for follow-up calls")
	}
}

func TestDelegationParity_PreToolUse_PendingInjectionWarningSurvivesHardDeny(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.AllowDelegation = false

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	state.SetPendingInjectionAlert("pending injection alert")
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "investigate repository"},
		CWD:       projectRoot,
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload pending-alert deny: %v", err)
	}
	if resp.Decision != policy.VerdictDeny {
		t.Fatalf("delegation decision = %q, want deny (reason=%s)", resp.Decision, resp.Reason)
	}
	if !strings.Contains(resp.Reason, "suspicious patterns") || !strings.Contains(resp.Reason, "pending injection alert") {
		t.Fatalf("deny reason = %q, want suspicious-output warning with detail", resp.Reason)
	}
}

func TestDelegationParity_PreToolUse_RecentlyReadUntrustedDoesNotForceApproval(t *testing.T) {
	state := session.NewState(t.TempDir())
	state.MarkUntrustedRead()

	if delegationRequiresApproval(state) {
		t.Fatal("RecentlyReadUntrusted alone should not force delegation approval; only the taint/elevated/pending-alert rules should gate")
	}
}

func TestDelegationParity_SubagentStart_RiskySessionStates(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*session.State)
	}{
		{
			name: "tainted mcp server",
			mutate: func(state *session.State) {
				state.AddTaintedMCPServer("jira")
			},
		},
		{
			name: "elevated posture",
			mutate: func(state *session.State) {
				state.RaisePosture(policy.PostureStateElevated)
			},
		},
		{
			name: "pending injection alert",
			mutate: func(state *session.State) {
				state.SetPendingInjectionAlert("pending injection alert")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			l := lease.DefaultLease()

			stateDir := session.StateDir(projectRoot)
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatalf("mkdir state: %v", err)
			}
			if err := l.Save(stateDir + "/lease.json"); err != nil {
				t.Fatalf("save lease: %v", err)
			}

			state := session.NewState(projectRoot)
			if err := state.Save(); err != nil {
				t.Fatalf("save initial session: %v", err)
			}
			tc.mutate(state)
			if err := state.Save(); err != nil {
				t.Fatalf("save mutated session: %v", err)
			}

			buf, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
				HookEventName: "SubagentStart",
				AgentName:     "general-purpose",
				Tools:         []string{"Read"},
			})
			if err != nil {
				t.Fatalf("EvaluateSubagentStart: %v", err)
			}
			if len(buf) == 0 {
				t.Fatalf("SubagentStart after %s: expected blocked or gated response, got no output", tc.name)
			}

			var resp struct {
				HookSpecificOutput struct {
					PermissionDecision string `json:"permissionDecision"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(buf, &resp); err != nil {
				t.Fatalf("unmarshal response: %v\nraw: %s", err, string(buf))
			}
			if resp.HookSpecificOutput.PermissionDecision == "allow" {
				t.Fatalf("SubagentStart after %s: expected blocked or gated decision, got allow", tc.name)
			}
		})
	}
}

func TestDelegationParity_SubagentStart_RecentlyReadUntrustedPreservesReadOnlyDelegation(t *testing.T) {
	cases := []struct {
		name  string
		tools []string
		want  string
	}{
		{
			name:  "read-only subagent",
			tools: []string{"Read"},
			want:  "",
		},
		{
			name:  "dangerous-tools subagent",
			tools: []string{"Read", "Bash"},
			want:  "ask",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			projectRoot := t.TempDir()
			l := lease.DefaultLease()

			stateDir := session.StateDir(projectRoot)
			if err := os.MkdirAll(stateDir, 0o700); err != nil {
				t.Fatalf("mkdir state: %v", err)
			}
			if err := l.Save(stateDir + "/lease.json"); err != nil {
				t.Fatalf("save lease: %v", err)
			}

			state := session.NewState(projectRoot)
			if err := state.Save(); err != nil {
				t.Fatalf("save initial session: %v", err)
			}
			state.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
			state.MarkUntrustedRead()
			if err := state.Save(); err != nil {
				t.Fatalf("save untrusted session: %v", err)
			}

			buf, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
				HookEventName: "SubagentStart",
				AgentName:     "general-purpose",
				Tools:         tc.tools,
			})
			if err != nil {
				t.Fatalf("EvaluateSubagentStart: %v", err)
			}

			if tc.want == "" {
				if len(buf) != 0 {
					t.Fatalf("SubagentStart after untrusted read with %v: expected allow/no output, got %s", tc.tools, string(buf))
				}
				return
			}

			if len(buf) == 0 {
				t.Fatalf("SubagentStart after untrusted read with %v: expected %s response, got no output", tc.tools, tc.want)
			}

			var resp struct {
				HookSpecificOutput struct {
					PermissionDecision string `json:"permissionDecision"`
				} `json:"hookSpecificOutput"`
			}
			if err := json.Unmarshal(buf, &resp); err != nil {
				t.Fatalf("unmarshal response: %v\nraw: %s", err, string(buf))
			}
			if resp.HookSpecificOutput.PermissionDecision != tc.want {
				t.Fatalf("SubagentStart after untrusted read with %v: decision = %q, want %q", tc.tools, resp.HookSpecificOutput.PermissionDecision, tc.want)
			}
		})
	}
}
