package hooks

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
)

func TestRecordedDecisionFor(t *testing.T) {
	off := lease.DefaultLease()
	on := lease.DefaultLease()
	on.ObserveOnly = true
	if got := recordedDecisionFor(off, policy.VerdictDeny); got != "deny" {
		t.Errorf("enforcement deny = %q, want deny", got)
	}
	if got := recordedDecisionFor(on, policy.VerdictDeny); got != "would_deny" {
		t.Errorf("observe deny = %q, want would_deny", got)
	}
	if got := recordedDecisionFor(on, policy.VerdictAsk); got != "would_ask" {
		t.Errorf("observe ask = %q, want would_ask", got)
	}
}

func lastDecision(t *testing.T, projectRoot string) ledger.Entry {
	t.Helper()
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("ledger is empty")
	}
	return entries[len(entries)-1]
}

func TestObserveMode_PostureWriteDowngradedButRecorded(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.ObserveOnly = true
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": ".claude/settings.json"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	// Wire response must not block in observe mode.
	if resp.Decision != "allow" {
		t.Errorf("observe posture write: expected allow on the wire, got %s", resp.Decision)
	}
	if !strings.Contains(resp.Reason, "observe-only") || !strings.Contains(resp.Reason, "would ask") {
		t.Errorf("observe reason missing annotation: %q", resp.Reason)
	}
	// Ledger must record the would-be verdict.
	entry := lastDecision(t, projectRoot)
	if entry.Decision != "would_ask" {
		t.Errorf("ledger decision = %q, want would_ask", entry.Decision)
	}
}

func TestObserveMode_NormalReadRecordsWouldAllow(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.ObserveOnly = true
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "src/main.go"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("observe normal read: expected allow, got %s", resp.Decision)
	}
	if entry := lastDecision(t, projectRoot); entry.Decision != "would_allow" {
		t.Errorf("ledger decision = %q, want would_allow", entry.Decision)
	}
}

// Observe mode never suppresses a control-plane integrity block: a deny-all
// session still denies, because measuring rollout friction must not silently
// proceed past a compromised control plane.
func TestObserveMode_DenyAllStillBlocks(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.ObserveOnly = true
	state := newTestSession(t, projectRoot)
	state.SetDenyAll("test: posture tamper detected")

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "src/main.go"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("observe + deny-all: expected deny (not suppressed), got %s", resp.Decision)
	}
}
