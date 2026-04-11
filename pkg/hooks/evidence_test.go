package hooks

import (
	"os"
	"strings"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func TestEnvLogToolContent(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	if !EnvLogToolContent() {
		t.Fatal("expected evidence logging env helper to return true")
	}
	t.Setenv("SIR_LOG_TOOL_CONTENT", "")
	if EnvLogToolContent() {
		t.Fatal("expected evidence logging env helper to return false")
	}
}

func TestPostEvaluate_EvidencePopulatedWhenEnvSet(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	resp, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Bash",
		ToolInput:  map[string]interface{}{"command": "echo credentials"},
		ToolOutput: testsecrets.AWSAccessKey(),
	}, lease.DefaultLease(), state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow response, got %q", resp.Decision)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry")
	}
	last := entries[len(entries)-1]
	if last.Evidence == "" {
		t.Fatal("expected evidence to be recorded")
	}
	if strings.Contains(last.Evidence, testsecrets.AWSAccessKey()) {
		t.Fatalf("expected evidence to redact secret, got %q", last.Evidence)
	}
	if !strings.Contains(last.Evidence, "[REDACTED:aws_access_key]") {
		t.Fatalf("expected redacted aws marker, got %q", last.Evidence)
	}
}

func TestPostEvaluate_EvidenceEmptyWhenEnvUnset(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Bash",
		ToolInput:  map[string]interface{}{"command": "echo credentials"},
		ToolOutput: testsecrets.AWSAccessKey(),
	}, lease.DefaultLease(), state, projectRoot); err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry")
	}
	if entries[len(entries)-1].Evidence != "" {
		t.Fatalf("expected no evidence when env unset, got %q", entries[len(entries)-1].Evidence)
	}
}

// TestPostEvaluate_AllowTraceWhenEnvSetCleanOutput covers Korman's tier-2
// investigation gap: a clean tool call (no credential or injection alert)
// should still leave redacted evidence in the ledger when the operator has
// opted in with SIR_LOG_TOOL_CONTENT=1.
func TestPostEvaluate_AllowTraceWhenEnvSetCleanOutput(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	resp, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Bash",
		ToolInput:  map[string]interface{}{"command": "echo hello"},
		ToolOutput: "hello\nworld\n",
	}, lease.DefaultLease(), state, projectRoot)
	if err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Fatalf("expected allow response, got %q", resp.Decision)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one tool_trace ledger entry, got %d", len(entries))
	}
	last := entries[0]
	if last.Verb != "tool_trace" {
		t.Fatalf("expected verb tool_trace, got %q", last.Verb)
	}
	if last.Decision != "allow" {
		t.Fatalf("expected decision allow, got %q", last.Decision)
	}
	if last.Evidence == "" {
		t.Fatal("expected redacted evidence to be recorded for clean allow path")
	}
	if !strings.Contains(last.Evidence, "hello") {
		t.Fatalf("expected clean content to pass through redactor, got %q", last.Evidence)
	}
}

// TestPostEvaluate_NoAllowTraceWhenEnvUnset confirms the env-gate default is
// silent. Without SIR_LOG_TOOL_CONTENT=1, a clean tool call must leave no
// ledger trace at all (existing privacy default).
func TestPostEvaluate_NoAllowTraceWhenEnvUnset(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Bash",
		ToolInput:  map[string]interface{}{"command": "echo hello"},
		ToolOutput: "hello\nworld\n",
	}, lease.DefaultLease(), state, projectRoot); err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no ledger entries when env unset, got %d", len(entries))
	}
}

// TestPostEvaluate_AllowTraceRedactsCredentialOnNonAlertTool covers the
// redaction guarantee on a tool call that does not trigger an alert
// (Write never runs the credential scanner). Even though the output
// contains an AWS key, the tool_trace entry must go through RedactContent
// and persist the [REDACTED] marker, never the raw secret.
func TestPostEvaluate_AllowTraceRedactsCredentialOnNonAlertTool(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Write",
		ToolInput:  map[string]interface{}{"file_path": "/tmp/x"},
		ToolOutput: "saved: " + testsecrets.AWSAccessKey(),
	}, lease.DefaultLease(), state, projectRoot); err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one tool_trace entry, got %d", len(entries))
	}
	last := entries[0]
	if last.Verb != "tool_trace" {
		t.Fatalf("expected verb tool_trace, got %q", last.Verb)
	}
	if strings.Contains(last.Evidence, testsecrets.AWSAccessKey()) {
		t.Fatalf("expected redaction to remove raw credential from tool_trace evidence, got %q", last.Evidence)
	}
	if !strings.Contains(last.Evidence, "[REDACTED:aws_access_key]") {
		t.Fatalf("expected [REDACTED:aws_access_key] marker in tool_trace evidence, got %q", last.Evidence)
	}
}

// TestPostEvaluate_AllowTraceSuppressedWhenAlertFired confirms dedup: when
// the credential scanner or MCP injection scanner has already written an
// alert entry for the same tool call, we must not also write a tool_trace
// entry carrying the same redacted evidence. The existing ordering test
// in mcp_injection_flow_test.go pins the contract; this one nails down
// the non-MCP path for Read/Edit/Bash.
func TestPostEvaluate_AllowTraceSuppressedWhenAlertFired(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if _, err := postEvaluatePayload(&PostHookPayload{
		ToolName:   "Bash",
		ToolInput:  map[string]interface{}{"command": "cat creds"},
		ToolOutput: testsecrets.AWSAccessKey(),
	}, lease.DefaultLease(), state, projectRoot); err != nil {
		t.Fatalf("postEvaluatePayload: %v", err)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one alert entry (no duplicate tool_trace), got %d", len(entries))
	}
	if entries[0].Verb == "tool_trace" {
		t.Fatalf("expected credential alert entry, got tool_trace — alert suppression broken")
	}
	if entries[0].AlertType != "credential_in_output" {
		t.Fatalf("expected credential_in_output alert, got %q", entries[0].AlertType)
	}
}

func TestPreToolUse_MCPEvidencePopulatedWhenEnvSet(t *testing.T) {
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")
	t.Setenv("HOME", t.TempDir())

	projectRoot := t.TempDir()
	state := session.NewState(projectRoot)
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	resp, err := evaluatePayload(&HookPayload{
		ToolName: "mcp__evil-server__record",
		ToolInput: map[string]interface{}{
			"customerData": map[string]interface{}{
				"AWS_ACCESS_KEY_ID": testsecrets.AWSAccessKey(),
			},
		},
	}, lease.DefaultLease(), state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Fatalf("expected deny response, got %q", resp.Decision)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry")
	}
	last := entries[len(entries)-1]
	if last.Evidence == "" {
		t.Fatal("expected MCP args evidence to be recorded")
	}
	if strings.Contains(last.Evidence, testsecrets.AWSAccessKey()) {
		t.Fatalf("expected MCP evidence to redact secret, got %q", last.Evidence)
	}
	if !strings.Contains(last.Evidence, "[REDACTED:aws_access_key]") {
		t.Fatalf("expected redacted aws marker, got %q", last.Evidence)
	}
}
