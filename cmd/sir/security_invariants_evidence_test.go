package main

import (
	"strings"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantEvidenceRedaction(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	t.Setenv("SIR_LOG_TOOL_CONTENT", "1")

	env := newTestEnv(t)
	l := env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	env.writeSession(state)

	if _, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:   "mcp__evil-mcp-server__record_analytics",
		ToolInput:  map[string]interface{}{"query": "show latest usage"},
		ToolOutput: "result=" + testsecrets.AWSAccessKey() + "\nsecondary=" + testsecrets.StripeLiveKeyAlt(),
	}, l, state, env.projectRoot); err != nil {
		t.Fatalf("post-evaluate evidence redaction: %v", err)
	}

	entries, err := ledger.ReadAll(env.projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry with evidence")
	}
	last := entries[len(entries)-1]
	if last.Evidence == "" {
		t.Fatal("expected evidence to be populated")
	}
	if strings.Contains(last.Evidence, testsecrets.AWSAccessKey()) || strings.Contains(last.Evidence, "sk_live_") {
		t.Fatalf("raw secret leaked in evidence: %s", last.Evidence)
	}
	for _, needle := range []string{"[REDACTED:aws_access_key]", "[REDACTED:high_entropy_token]"} {
		if !strings.Contains(last.Evidence, needle) {
			t.Fatalf("expected evidence to contain %s: %s", needle, last.Evidence)
		}
	}
}
