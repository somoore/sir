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
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
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

	// Build a SubagentStart payload and pipe it through os.Stdin, capturing
	// the hook response from os.Stdout. This is the same contract the real
	// hook uses, so the test exercises the full EvaluateSubagentStart path.
	payloadJSON, err := json.Marshal(SubagentPayload{
		HookEventName: "SubagentStart",
		AgentName:     "general-purpose",
		Tools:         []string{"Read", "Bash"},
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	origStdin, origStdout := os.Stdin, os.Stdout
	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
	}()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe in: %v", err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe out: %v", err)
	}
	os.Stdin = inR
	os.Stdout = outW

	if _, err := inW.Write(payloadJSON); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	inW.Close()

	done := make(chan error, 1)
	go func() {
		done <- EvaluateSubagentStart(projectRoot, &agent.ClaudeAgent{})
	}()

	if err := <-done; err != nil {
		outW.Close()
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	outW.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, outR); err != nil {
		t.Fatalf("read stdout: %v", err)
	}

	if buf.Len() == 0 {
		t.Fatal("SubagentStart + secret session: expected a deny response, got no response (fail-open)")
	}

	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw: %s", err, buf.String())
	}

	if resp.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("SubagentStart + secret session: decision = %q, want %q (Rust returns deny; Go must never be more permissive). reason: %s",
			resp.HookSpecificOutput.PermissionDecision, "deny",
			resp.HookSpecificOutput.PermissionDecisionReason)
	}
}
