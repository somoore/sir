package postflight

import (
	"fmt"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
)

func SentinelMutationEntry(toolName, target string, changed []string) *ledger.Entry {
	return &ledger.Entry{
		ToolName:  toolName,
		Verb:      "sentinel_mutation",
		Target:    target,
		Decision:  "alert",
		Reason:    fmt.Sprintf("sentinel files modified during install: %v", changed),
		Severity:  "HIGH",
		AlertType: "sentinel_mutation",
	}
}

func CredentialOutputEntry(toolName, target string, patternNames []string, evidence string) *ledger.Entry {
	entry := &ledger.Entry{
		ToolName:  toolName,
		Verb:      string(policy.VerbCredentialDetected),
		Target:    target,
		Decision:  "alert",
		Reason:    fmt.Sprintf("structured credentials in tool output: %v", patternNames),
		Severity:  "HIGH",
		AlertType: "credential_in_output",
	}
	if evidence != "" {
		entry.Evidence = evidence
	}
	return entry
}

func MCPCredentialOutputEntry(toolName, serverName string, patternNames []string, evidence string) *ledger.Entry {
	entry := &ledger.Entry{
		ToolName:  toolName,
		Verb:      string(policy.VerbCredentialDetected),
		Target:    serverName,
		Decision:  "alert",
		Reason:    fmt.Sprintf("structured credentials in MCP output: %v", patternNames),
		Severity:  "HIGH",
		AlertType: "credential_in_output",
	}
	if evidence != "" {
		entry.Evidence = evidence
	}
	return entry
}

func MCPInjectionEntry(toolName, serverName string, patternNames []string, severity, evidence string) *ledger.Entry {
	entry := &ledger.Entry{
		ToolName:  toolName,
		Verb:      string(policy.VerbMcpInjectionDetected),
		Target:    serverName,
		Decision:  "alert",
		Reason:    fmt.Sprintf("injection signals detected: %v", patternNames),
		Severity:  severity,
		AlertType: "mcp_injection",
	}
	if evidence != "" {
		entry.Evidence = evidence
	}
	return entry
}
