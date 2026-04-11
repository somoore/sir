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
// When the caller has already detected that the PostToolUse payload read
// a sensitive path (e.g. ~/.aws/credentials, a .env file), sensitiveTarget
// is true and we mark the ledger Entry with Sensitivity="secret". The
// telemetry exporter then hashes Target via RedactTarget before emitting
// to OTLP, so raw sensitive paths never leave the host even on clean
// allow-path reads. Secret-session context is already exported separately
// via the sir.session.secret OTLP attribute, so we intentionally do NOT
// over-broaden the per-entry sensitivity label to the whole session.
//
// This trace is additive only on non-alert paths. When any alert-path
// ledger entry (credential_in_output, mcp_credential_leak, mcp_injection,
// sentinel_mutation) was successfully appended for the same tool call,
// the caller suppresses the tool_trace write — the alert entry already
// carries the redacted evidence and duplicating it is noise.
func applyPostEvaluateAllowTrace(payload *PostHookPayload, state *session.State, projectRoot string, ag agent.Agent, sensitiveTarget bool) {
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
	if sensitiveTarget {
		entry.Sensitivity = "secret"
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		return
	}
	emitTelemetryEvent(entry, state, ag)
}
