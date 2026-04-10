// Package hooks — mcp_defense.go implements MCP response injection scanning,
// MCP credential argument scanning, and related signal types.
package hooks

import (
	"github.com/somoore/sir/pkg/hooks/evidence"
)

type InjectionSignal = evidence.InjectionSignal

// ScanMCPResponseForInjection scans MCP tool output for prompt injection signals.
// Returns all matched signals. The output is never stored verbatim in the ledger;
// only pattern names and truncated context are returned.
func ScanMCPResponseForInjection(output string) []InjectionSignal {
	return evidence.ScanMCPResponseForInjection(output)
}

// HighestSeverity returns the highest severity among a set of injection signals.
// Order: HIGH > MEDIUM > LOW. Returns "" if signals is empty.
func HighestSeverity(signals []InjectionSignal) string {
	return evidence.HighestSeverity(signals)
}

// ScanMCPArgsForCredentials checks MCP tool arguments for credential patterns.
// Called for ALL untrusted MCP server calls (not just secret sessions).
// Returns (found, patternHint) where patternHint describes what was found
// (never the actual credential value).
func ScanMCPArgsForCredentials(toolInput map[string]interface{}) (bool, string) {
	return evidence.ScanMCPArgsForCredentials(toolInput)
}

// ScanStringForCredentials checks a raw string for credential patterns.
// Used by mcp-proxy to scan stderr output from MCP server processes.
func ScanStringForCredentials(s string) (bool, string) {
	return evidence.ScanStringForCredentials(s)
}
