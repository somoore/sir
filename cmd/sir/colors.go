package main

import "os"

// ---------- ANSI color helpers for audit (mirrors pkg/hooks/messages.go, unexported there) ----------

const (
	auditReset   = "\033[0m"
	auditBold    = "\033[1m"
	auditDim     = "\033[2m"
	auditGreen   = "\033[32m"
	auditYellow  = "\033[33m"
	auditCyan    = "\033[36m"
	auditBoldRed = "\033[1;31m"
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
