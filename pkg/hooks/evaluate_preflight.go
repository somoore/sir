package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func evaluateMCPCredentialLeak(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if l.IsTrustedMCPServer(serverName) {
		return nil, false
	}
	found, patternHint := ScanMCPArgsForCredentials(payload.ToolInput)
	if !found {
		return nil, false
	}

	entry := &ledger.Entry{
		ToolName:  payload.ToolName,
		Verb:      string(policy.VerbMcpCredentialLeak),
		Target:    serverName,
		Decision:  "deny",
		Reason:    fmt.Sprintf("credential pattern in MCP args: %s", patternHint),
		Severity:  "HIGH",
		AlertType: "mcp_credential",
	}
	if EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}

	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatDenyMCPCredential(payload.ToolName, serverName, patternHint),
	}, true
}

func evaluateTaintedMCPServer(payload *HookPayload, state *session.State) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !state.IsMCPServerTainted(serverName) || state.Posture != policy.PostureStateCritical {
		return nil, false
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   FormatAskPostureElevated("mcp_call", payload.ToolName, string(state.Posture), state.MCPInjectionSignals),
	}, true
}

func evaluateElevatedPosture(intent Intent, state *session.State) (*HookResponse, bool) {
	if state.Posture != policy.PostureStateElevated && state.Posture != policy.PostureStateCritical {
		return nil, false
	}
	if intent.Verb != policy.VerbStageWrite && intent.Verb != policy.VerbExecuteDryRun {
		return nil, false
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   FormatAskPostureElevated(string(intent.Verb), intent.Target, string(state.Posture), state.MCPInjectionSignals),
	}, true
}
