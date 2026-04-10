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
