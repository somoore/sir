package hooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func TestRawSecretReadGate_InlineRedactedView(t *testing.T) {
	projectRoot := t.TempDir()
	secret := "AKIAIOSFODNN7EXAMPLE"
	if err := os.WriteFile(filepath.Join(projectRoot, ".env"), []byte("AWS_ACCESS_KEY_ID="+secret+"\nDEBUG=true\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	l := lease.DefaultLease()
	l.DenyRawSecretReads = true
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": filepath.Join(projectRoot, ".env")},
		CWD:       projectRoot,
	}
	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected deny, got %s", resp.Decision)
	}
	// The redacted key inventory is handed back inline.
	if !strings.Contains(resp.Reason, "AWS_ACCESS_KEY_ID") || !strings.Contains(resp.Reason, "DEBUG") {
		t.Errorf("inline redacted view missing keys:\n%s", resp.Reason)
	}
	// The raw value must never appear.
	if strings.Contains(resp.Reason, secret) {
		t.Errorf("raw secret value leaked into deny reason:\n%s", resp.Reason)
	}
}

func TestRawSecretReadGate_DeniesUnderTeamProfile(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.DenyRawSecretReads = true // team/strict
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
		CWD:       projectRoot,
	}
	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("raw .env read under team profile: expected deny, got %s", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "sir secret view") {
		t.Errorf("deny message should point to the redacted view, got: %s", resp.Reason)
	}
	// Recorded in the ledger as a deny.
	if e := lastDecision(t, projectRoot); e.Decision != "deny" || e.Verb != "read_ref" {
		t.Errorf("ledger entry = %s/%s, want deny/read_ref", e.Decision, e.Verb)
	}
}

func TestRawSecretReadGate_NotDeniedUnderPersonalProfile(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease() // DenyRawSecretReads false
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
		CWD:       projectRoot,
	}
	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	// Personal profile: the gate does not fire (a sensitive read prompts, it is
	// not hard-denied by this gate).
	if resp.Decision == "deny" && strings.Contains(resp.Reason, "denies raw secret reads") {
		t.Errorf("personal profile should not hard-deny raw secret reads via the gate: %s", resp.Reason)
	}
}

// An explicit `sir approve path <secret>` grant must let the raw read through
// even under team/strict — the gate defers to the normal ask->grant->allow path.
func TestRawSecretReadGate_HonorsApprovalGrant(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.DenyRawSecretReads = true
	state := newTestSession(t, projectRoot)
	state.AddApprovalGrant(session.ApprovalGrant{Verb: "read_ref", Target: ".env", Scope: "once", UsesRemaining: 1})
	if err := state.Save(); err != nil { // persist so session integrity holds
		t.Fatalf("save state: %v", err)
	}

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
		CWD:       projectRoot,
	}
	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == "deny" {
		t.Fatalf("an approved raw read should not be denied by the gate; reason: %s", resp.Reason)
	}
}

func TestRawSecretReadGate_ObserveDowngrades(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.DenyRawSecretReads = true
	l.ObserveOnly = true
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
		CWD:       projectRoot,
	}
	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("observe mode must not block the gate, got %s", resp.Decision)
	}
	if e := lastDecision(t, projectRoot); e.Decision != "would_deny" {
		t.Errorf("observe ledger decision = %s, want would_deny", e.Decision)
	}
}
