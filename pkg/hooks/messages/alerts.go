package messages

import "strings"

// FormatPostureRestore formats the posture file auto-restore message.
func FormatPostureRestore(file string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBoldRed, "sir ALERT"))
	b.WriteString(": ")
	b.WriteString(colorize(colorCyan, file))
	b.WriteString(" was modified and auto-restored\n\n")
	b.WriteString("  reason: This is a security configuration file.\n")
	b.WriteString("           Unauthorized changes are reverted automatically.\n\n")
	b.WriteString("  details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

// FormatSessionCleared formats the session clear confirmation.
func FormatSessionCleared() string {
	var b strings.Builder
	b.WriteString(colorize(colorGreen, "\u00b7 allow"))
	b.WriteString(" \u00b7 transient runtime restrictions cleared")
	b.WriteString("\n\n")
	b.WriteString("  External network access and prompt-driving session taint are cleared.\n\n")
	b.WriteString("  Note: Secrets read earlier are still in model memory. If you need\n")
	b.WriteString("        full isolation from those reads, start a fresh agent session.\n\n")
	b.WriteString("  details: ")
	b.WriteString(colorize(colorDim, "sir why"))
	return b.String()
}

// FormatDenyMCPCredential formats a DENY for credential patterns detected in
// MCP tool arguments.
func FormatDenyMCPCredential(toolName, serverName, patternHint string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBold+colorRed, "\u00d7 deny"))
	b.WriteString(" \u00b7 MCP credential leak\n\n")
	b.WriteString("  Tool:    ")
	b.WriteString(colorize(colorCyan, toolName))
	b.WriteString("\n")
	b.WriteString("  Server:  ")
	b.WriteString(serverName)
	b.WriteString("\n\n")
	b.WriteString("  reason: The tool arguments look like they include a credential value,\n")
	b.WriteString("           and this MCP server is not on your trusted list. Sending\n")
	b.WriteString("           credentials to an untrusted MCP server is blocked regardless\n")
	b.WriteString("           of session state.\n")
	b.WriteString("           Pattern: ")
	b.WriteString(patternHint)
	b.WriteString("\n\n")
	b.WriteString("  fix: sir trust ")
	b.WriteString(serverName)
	b.WriteString("  (only do this if this server is designed to receive tokens)\n\n")
	b.WriteString("  details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

// FormatMCPInjectionWarning formats a stderr warning for detected injection signals.
func FormatMCPInjectionWarning(serverName, severity string, patterns []string) string {
	patternList := strings.Join(patterns, ", ")
	if len(patternList) > 80 {
		patternList = patternList[:77] + "..."
	}

	sevColor := colorDim
	switch severity {
	case "HIGH":
		sevColor = colorBoldRed
	case "MEDIUM":
		sevColor = colorYellow
	}

	var b strings.Builder
	b.WriteString(colorize(colorBoldRed, "sir ALERT"))
	b.WriteString(": Suspicious instructions detected in external tool response\n\n")
	b.WriteString("  Server:   ")
	b.WriteString(colorize(colorCyan, serverName))
	b.WriteString("\n")
	b.WriteString("  Severity: ")
	b.WriteString(colorize(sevColor, severity))
	b.WriteString("\n")
	b.WriteString("  Patterns: ")
	b.WriteString(patternList)
	b.WriteString("\n\n")
	b.WriteString("  sir has raised the alert level. Subsequent calls to this\n")
	b.WriteString("  server may require your approval.\n\n")
	b.WriteString("  details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

// FormatElicitationWarning formats a stderr warning for credential harvesting in elicitation.
func FormatElicitationWarning(patterns []string) string {
	patternList := strings.Join(patterns, ", ")
	if len(patternList) > 80 {
		patternList = patternList[:77] + "..."
	}

	var b strings.Builder
	b.WriteString(colorize(colorBold+colorYellow, "? ask"))
	b.WriteString(": This question may be harvesting credentials\n\n")
	b.WriteString("  Patterns: ")
	b.WriteString(patternList)
	b.WriteString("\n\n")
	b.WriteString("  Do NOT paste API keys, tokens, or passwords into the agent chat.\n")
	b.WriteString("  Store credentials in .env files and let sir gate access.\n\n")
	b.WriteString("  details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}
