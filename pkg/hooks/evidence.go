package hooks

import hooksevidence "github.com/somoore/sir/pkg/hooks/evidence"

func marshalMCPEvidence(toolInput map[string]interface{}) string {
	return hooksevidence.MarshalMCP(toolInput)
}

func redactToolOutputEvidence(output string) string {
	return hooksevidence.RedactToolOutput(output)
}

func redactToolOutputEvidenceIfEnabled(output string) string {
	if !EnvLogToolContent() {
		return ""
	}
	return redactToolOutputEvidence(output)
}
