package hooks

import (
	"fmt"
	"os"
	"strings"

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

// Approved MCP calls still need a gate when the session is secret or when the
// payload points at a file already carrying secret lineage.
func evaluateTaintedMCPInput(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	if state.SecretSession {
		return &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   "MCP calls require approval while the session carries credentials.",
		}, true
	}

	targets := derivedSecretLineageTargets(payload.ToolInput, projectRoot, state)
	if len(targets) == 0 {
		return nil, false
	}
	target := targets[0]
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   fmt.Sprintf("MCP call touching %s requires approval because it carries secret lineage.", target),
	}, true
}

func derivedSecretLineageTargets(input any, projectRoot string, state *session.State) []string {
	seen := make(map[string]struct{})
	var targets []string
	var walk func(any, string)
	walk = func(value any, key string) {
		switch typed := value.(type) {
		case string:
			if typed == "" || !isPathBearingMCPKey(key) {
				return
			}
			if _, ok := seen[typed]; ok {
				return
			}
			for _, label := range state.DerivedLabelsForPath(ResolveTarget(projectRoot, typed)) {
				if label.Sensitivity != "secret" {
					continue
				}
				seen[typed] = struct{}{}
				targets = append(targets, typed)
				return
			}
		case []interface{}:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]any:
			for childKey, item := range typed {
				walk(item, childKey)
			}
		}
	}
	walk(input, "")
	return targets
}

func isPathBearingMCPKey(key string) bool {
	normalized := normalizeMCPArgKey(key)
	return strings.HasSuffix(normalized, "path") || strings.HasSuffix(normalized, "paths")
}

func normalizeMCPArgKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
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
