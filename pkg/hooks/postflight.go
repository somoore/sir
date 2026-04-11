package hooks

import (
	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	internalpostflight "github.com/somoore/sir/pkg/hooks/internal/postflight"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
)

func extractPostEvaluateTarget(payload *PostHookPayload) string {
	return internalpostflight.ExtractTarget(payload)
}

func recordSensitiveTargetFromPostPayload(payload *PostHookPayload, l *lease.Lease, projectRoot string) string {
	return internalpostflight.SensitiveTarget(
		payload,
		func(target string) bool { return IsSensitivePathResolvedIn(projectRoot, target, l) },
		hookclassify.IsEnvCommand,
	)
}

func sentinelMutationEntry(payload *PostHookPayload, pendingCommand string, changed []string) *ledger.Entry {
	return internalpostflight.SentinelMutationEntry(payload.ToolName, pendingCommand, changed)
}

func credentialOutputEntry(payload *PostHookPayload, target string, patternNames []string, evidence string) *ledger.Entry {
	return internalpostflight.CredentialOutputEntry(payload.ToolName, target, patternNames, evidence)
}

func mcpCredentialOutputEntry(payload *PostHookPayload, serverName string, patternNames []string, evidence string) *ledger.Entry {
	return internalpostflight.MCPCredentialOutputEntry(payload.ToolName, serverName, patternNames, evidence)
}

func mcpInjectionEntry(payload *PostHookPayload, serverName string, patternNames []string, severity, evidence string) *ledger.Entry {
	return internalpostflight.MCPInjectionEntry(payload.ToolName, serverName, patternNames, severity, evidence)
}

func toolTraceEntry(payload *PostHookPayload, target, evidence string) *ledger.Entry {
	return internalpostflight.ToolTraceEntry(payload.ToolName, target, evidence)
}
