package messages

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func AgentDisplayName(id string) string {
	switch id {
	case "claude", "":
		return "Claude"
	case "codex":
		return "Codex"
	case "gemini":
		return "Gemini"
	}
	return "Claude"
}

var hostRE = regexp.MustCompile(`https?://[^\s'"\x60]+|\b[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z][a-zA-Z0-9-]*(?::\d+)?\b`)

func ExtractHostForMessage(dest string) (string, bool) {
	dest = strings.TrimSpace(dest)
	if dest == "" {
		return "", false
	}
	match := hostRE.FindString(dest)
	if match == "" || strings.ContainsAny(match, "%{}") {
		return "", false
	}
	if strings.HasPrefix(match, "http://") || strings.HasPrefix(match, "https://") {
		if u, err := url.Parse(match); err == nil && u.Host != "" {
			return u.Host, true
		}
	}
	return match, true
}

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorCyan    = "\033[36m"
	colorBoldRed = "\033[1;31m"
)

func ColorsEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("CLICOLOR") == "0" {
		return false
	}
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func colorize(color, text string) string {
	if !ColorsEnabled() {
		return text
	}
	return color + text + colorReset
}

func FormatBlock(action, causalChain, fix string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBold+colorRed, "sir BLOCKED"))
	b.WriteString(": ")
	b.WriteString(action)
	b.WriteString("\n\n")
	b.WriteString("  Why: ")
	b.WriteString(causalChain)
	b.WriteString("\n\n")
	b.WriteString("  Fix: ")
	b.WriteString(fix)
	b.WriteString("\n\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

func FormatAsk(action, reason, consequence string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBold+colorYellow, "sir: approval needed"))
	b.WriteString(" -- ")
	b.WriteString(action)
	b.WriteString("\n\n")
	b.WriteString("  Why: ")
	b.WriteString(reason)
	b.WriteString("\n")
	if consequence != "" {
		b.WriteString("       ")
		b.WriteString(consequence)
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

func FormatAskSensitive(target string, scope string) string {
	if scope == "" {
		scope = "turn"
	}
	var b strings.Builder
	b.WriteString(colorize(colorBold+colorYellow, "sir: approval needed"))
	b.WriteString(" -- Read ")
	b.WriteString(colorize(colorCyan, target))
	b.WriteString("\n\n")
	b.WriteString("  Why: This file contains credentials. If you approve, sir will\n")
	b.WriteString("       restrict external network requests to prevent leaks.\n\n")
	if scope == "turn" {
		b.WriteString("  Scope: ")
		b.WriteString(colorize(colorGreen, "TURN"))
		b.WriteString(" — clears automatically when the agent finishes responding.\n\n")
	} else {
		b.WriteString("  Scope: ")
		b.WriteString(colorize(colorYellow, "SESSION"))
		b.WriteString(" — persists until you run `sir unlock`.\n\n")
	}
	b.WriteString("  If something gets stuck after approval:\n")
	b.WriteString("       sir unlock                (lift the secret-session lock)\n")
	b.WriteString("       sir allow-host <host>     (permanently allow a specific host)\n\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

func FormatFatal(action, consequence, remedy string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBoldRed, "sir FATAL"))
	b.WriteString(": ")
	b.WriteString(action)
	b.WriteString("\n\n")
	b.WriteString("  Why: ")
	b.WriteString(consequence)
	b.WriteString("\n\n")
	b.WriteString("  Fix: Open a NEW terminal outside the agent\n")
	b.WriteString("       ")
	b.WriteString(remedy)
	b.WriteString("\n\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

func formatEmergencyBox(lines []string) string {
	useBoxChars := ColorsEnabled()
	var border, footer, rowL, rowR string
	if useBoxChars {
		border = "╔══════════════════════════════════════════════════════════╗"
		footer = "╚══════════════════════════════════════════════════════════╝"
		rowL = "║"
		rowR = "║"
	} else {
		border = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		footer = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
		rowL = "!"
		rowR = "!"
	}

	var b strings.Builder
	b.WriteString(colorize(colorBoldRed, border))
	b.WriteString("\n")
	for _, line := range lines {
		row := fmt.Sprintf("%s  %-56s%s", rowL, line, rowR)
		b.WriteString(colorize(colorBoldRed, row))
		b.WriteString("\n")
	}
	b.WriteString(colorize(colorBoldRed, footer))
	return b.String()
}

func FormatDenyAll(reason string) string {
	truncated := reason
	if len(truncated) > 56 {
		truncated = truncated[:53] + "..."
	}
	return formatEmergencyBox([]string{
		"sir EMERGENCY: All tool calls blocked",
		"",
		"What: " + truncated,
		"",
		"Fix:  Run `sir doctor` in a new terminal",
		"      outside the current agent session",
	})
}

func FormatHookTamper(file string) string {
	truncated := file
	if len(truncated) > 48 {
		truncated = "..." + truncated[len(truncated)-45:]
	}
	return formatEmergencyBox([]string{
		"sir FATAL: Security configuration was modified",
		"",
		"What: " + truncated + " changed without approval",
		"Why:  All tool calls are blocked until verified",
		"",
		"Fix:  Open a NEW terminal outside the agent",
		"      Run: sir doctor",
		"      Then: sir install --force",
	})
}

func FormatInstallPreview(hooksPath, stateDir, leasePath string, postureFiles []string) string {
	var b strings.Builder
	b.WriteString("sir will create/modify the following:\n\n")
	b.WriteString(fmt.Sprintf("  %s  %s\n", colorize(colorBold, "hooks"), hooksPath))
	b.WriteString(fmt.Sprintf("  %s  %s\n", colorize(colorBold, "state"), stateDir))
	b.WriteString(fmt.Sprintf("  %s  %s\n", colorize(colorBold, "lease"), leasePath))
	if len(postureFiles) > 0 {
		b.WriteString(fmt.Sprintf("  %s  %d files (%s)\n", colorize(colorBold, "posture"), len(postureFiles), strings.Join(postureFiles, ", ")))
	}
	b.WriteString("\nProceed?")
	return b.String()
}

func FormatLeaseIntegrityFatal() string {
	return FormatFatal(
		"Security policy integrity check failed",
		"the lease hash changed outside sir or the policy file is corrupted",
		"run `sir doctor`, then `sir install --force` if you trust the new baseline",
	)
}

func FormatSessionIntegrityFatal() string {
	return FormatFatal(
		"Session integrity check failed",
		"the session file was modified outside sir or is corrupted",
		"run `sir doctor` and verify the session before resuming",
	)
}

func TruncateCmd(cmd string) string {
	if len(cmd) <= 60 {
		return cmd
	}
	return cmd[:57] + "..."
}
