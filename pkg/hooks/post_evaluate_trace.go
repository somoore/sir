package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// applyPostEvaluateAllowTrace writes a redacted tool_trace ledger entry for
// allow-path tool calls when SIR_LOG_TOOL_CONTENT=1 is set. Without this,
// sir's ledger is quiet on clean tool calls — an investigator can see that
// a tool was allowed but not reconstruct what it actually returned. Setting
// the env var opts into Korman's tier-2 investigation view at the cost of
// a larger ledger.
//
// Evidence is always routed through ledger.RedactContent (via the existing
// redactToolOutputEvidence helper), so known credential patterns are
// replaced with [REDACTED:<class>] markers before anything is persisted.
// There is no code path that writes a raw secret to disk, regardless of
// env-var configuration.
//
// This trace is additive: alert-path entries (credential_in_output,
// mcp_injection, sentinel_mutation, hook_tamper) continue to fire exactly
// as before and carry their own Evidence field. A tool call that trips an
// alert will produce both an alert entry and a tool_trace entry when the
// env var is set, so the two views of the same event stay separable in
// downstream SIEM queries.
func applyPostEvaluateAllowTrace(payload *PostHookPayload, state *session.State, projectRoot string, ag agent.Agent) {
	if !EnvLogToolContent() {
		return
	}
	if payload == nil || payload.ToolOutput == "" {
		return
	}

	evidence := redactToolOutputEvidence(payload.ToolOutput)
	if evidence == "" {
		return
	}

	target := extractPostEvaluateTarget(payload)
	if isToolMCP(payload.ToolName) {
		if serverName := extractMCPServerName(payload.ToolName); serverName != "" {
			target = serverName
		}
	}

	entry := toolTraceEntry(payload, target, evidence)
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		return
	}
	emitTelemetryEvent(entry, state, ag)
}
