package main

import "os"

// ANSI color helpers for CLI output.

const (
	auditReset      = "\033[0m"
	auditBold       = "\033[1m"
	auditDim        = "\033[2m"
	auditRed        = "\033[31m"
	auditGreen      = "\033[32m"
	auditYellow     = "\033[33m"
	auditCyan       = "\033[36m"
	auditBoldRed    = "\033[1;31m"
	auditBoldGreen  = "\033[1;32m"
	auditBoldYellow = "\033[1;33m"
	auditBoldCyan   = "\033[1;36m"
)

func auditColorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func ac(color, text string) string {
	if !auditColorsEnabled() {
		return text
	}
	return color + text + auditReset
}

// verdictGlyph returns the colored verdict glyph: allow → green ·, ask → yellow ?, deny → bold-red ×.
func verdictGlyph(decision string) string {
	switch decision {
	case "allow":
		return ac(auditGreen, "\u00b7")
	case "ask":
		return ac(auditYellow, "?")
	case "deny":
		return ac(auditBoldRed, "\u00d7")
	default:
		return ac(auditDim, "-")
	}
}

// decisionColor returns the ANSI color for a verdict string.
func decisionColor(decision string) string {
	switch decision {
	case "allow":
		return auditGreen
	case "ask":
		return auditYellow
	case "deny":
		return auditBoldRed
	default:
		return auditDim
	}
}
