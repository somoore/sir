package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// applyPostEvaluateOutputCredentialAnalysis runs the non-MCP output scan used by
// Read/Edit/Bash responses. Keep this isolated from orchestration so the output
// pass can stay easy to reason about without changing evaluation order.
// applyPostEvaluateOutputCredentialAnalysis returns true when a credential
// alert entry was appended to the ledger. Callers use this to suppress a
// duplicate tool_trace entry for the same allow-path tool call.
func applyPostEvaluateOutputCredentialAnalysis(payload *PostHookPayload, state *session.State, projectRoot string, ag agent.Agent) bool {
	if payload.ToolOutput == "" || isToolMCP(payload.ToolName) {
		return false
	}
	switch payload.ToolName {
	case "Read", "Edit", "Bash":
		credMatches := ScanOutputForCredentials(payload.ToolOutput)
		if len(credMatches) == 0 {
			return false
		}

		target := extractPostEvaluateTarget(payload)
		recordCredentialOutputEvidence(state, lineageSourceRef(payload, target), credMatches)

		patternNames := make([]string, 0, len(credMatches))
		for _, m := range credMatches {
			patternNames = append(patternNames, m.PatternName)
		}
		if !state.SecretSession {
			state.MarkSecretSession()
			fmt.Fprintf(os.Stderr, "sir: structured credentials detected in %s output: %v\n", payload.ToolName, patternNames)
			fmt.Fprintf(os.Stderr, "sir: session marked secret — external network requests are now restricted.\n")
			fmt.Fprintf(os.Stderr, "sir: to lift: sir unlock\n")
		}
		entry := credentialOutputEntry(payload, target, patternNames, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
		if err := ledger.Append(projectRoot, entry); err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			return false
		}
		emitTelemetryEvent(entry, state, ag)
		return true
	}
	return false
}

// applyPostEvaluateMCPOutputAnalysis runs the MCP-specific output scans.
// The credential scan and injection scan remain in the same order as the
// legacy inline implementation.
// applyPostEvaluateMCPOutputAnalysis returns true when at least one MCP alert
// entry (credential leak or injection) was appended to the ledger. Callers
// use this to suppress a duplicate tool_trace entry.
func applyPostEvaluateMCPOutputAnalysis(payload *PostHookPayload, state *session.State, projectRoot string, ag agent.Agent) bool {
	if !isToolMCP(payload.ToolName) || payload.ToolOutput == "" {
		return false
	}
	var appended bool

	serverName := extractMCPServerName(payload.ToolName)
	mcpCredMatches := ScanOutputForCredentials(payload.ToolOutput)
	if len(mcpCredMatches) > 0 {
		recordMCPCredentialEvidence(state, lineageSourceRef(payload, serverName), mcpCredMatches)

		patternNames := make([]string, 0, len(mcpCredMatches))
		for _, m := range mcpCredMatches {
			patternNames = append(patternNames, m.PatternName)
		}
		if !state.SecretSession {
			state.MarkSecretSession()
			fmt.Fprintf(os.Stderr, "sir: structured credentials detected in %s output.\n", payload.ToolName)
			fmt.Fprintf(os.Stderr, "sir: session marked secret — external network requests are now restricted.\n")
			fmt.Fprintf(os.Stderr, "sir: to lift: sir unlock\n")
		}
		entry := mcpCredentialOutputEntry(payload, serverName, patternNames, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
		if err := ledger.Append(projectRoot, entry); err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		} else {
			appended = true
		}
		emitTelemetryEvent(entry, state, ag)
	}

	signals := ScanMCPResponseForInjection(payload.ToolOutput)
	if len(signals) == 0 {
		return appended
	}

	severity := HighestSeverity(signals)
	recordMCPInjectionEvidence(state, lineageSourceRef(payload, serverName), severity)

	// Record signals and tainted server in session state.
	for _, sig := range signals {
		state.AddMCPInjectionSignal(sig.Pattern)
	}
	state.AddTaintedMCPServer(serverName)

	// Raise posture based on severity.
	switch severity {
	case "HIGH":
		state.RaisePosture(policy.PostureStateCritical)
	case "MEDIUM":
		state.RaisePosture(policy.PostureStateElevated)
	default:
		state.RaisePosture(policy.PostureStateElevated)
	}

	// Mark untrusted read — the response content is untrusted.
	state.MarkUntrustedRead()

	// Log to ledger (never log the actual output content).
	var patternNames []string
	for _, sig := range signals {
		patternNames = append(patternNames, sig.Pattern)
	}
	entry := mcpInjectionEntry(payload, serverName, patternNames, severity, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	} else {
		appended = true
	}
	emitTelemetryEvent(entry, state, ag)

	// Set pending injection alert so the next PreToolUse intercepts
	// and asks the developer before processing the tool call.
	// This closes the one-action window between detection and enforcement.
	if severity == "HIGH" {
		state.SetPendingInjectionAlert(fmt.Sprintf("MCP server %s returned prompt injection signals: %v", serverName, patternNames))
	}

	// Warn on stderr so the developer sees it in Claude Code context.
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintln(os.Stderr, FormatMCPInjectionWarning(serverName, severity, patternNames))

	return appended
}
