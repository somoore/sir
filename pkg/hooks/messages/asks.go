package messages

import (
	"fmt"
	"strings"
)

// FormatAskInstall formats an ASK message for a package not found in the lockfile.
func FormatAskInstall(pkgName, manager string) string {
	var b strings.Builder
	b.WriteString(colorize(colorBold+colorYellow, "sir: approval needed"))
	b.WriteString(" -- Install ")
	b.WriteString(colorize(colorCyan, pkgName))
	b.WriteString(fmt.Sprintf(" (%s)", manager))
	b.WriteString("\n\n")
	b.WriteString("  Why: This package is not in your lockfile. It could be a typosquat\n")
	b.WriteString("       or supply chain attack.\n\n")
	b.WriteString("  Approve to install, or deny to prevent.\n")
	b.WriteString("  Review the package before approving.\n\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}

func FormatAskPosture(target string) string {
	return FormatAsk(
		fmt.Sprintf("Write %s", target),
		"This file controls security settings. Approve to let the agent edit it.",
		"All writes to security configuration files require explicit approval.",
	)
}

func FormatAskEnvRead(cmd string) string {
	return FormatAsk(
		"Environment variable access",
		fmt.Sprintf("Environment variables may contain credentials. `%s` could expose them.", TruncateCmd(cmd)),
		"If you approve, sir will block external network requests to prevent leaks.",
	)
}

func FormatAskEphemeral(target string) string {
	return FormatAsk(
		fmt.Sprintf("Run %s", target),
		"npx downloads and runs remote code. Approve to proceed.",
		"Review the package before approving.",
	)
}

func FormatAskPersistence(cmd string) string {
	return FormatAsk(
		"Scheduled task",
		fmt.Sprintf("This can create scheduled tasks that outlive your session. `%s`", TruncateCmd(cmd)),
		"Scheduled tasks could leak data after sir is no longer watching.",
	)
}

func FormatAskSudo(cmd string) string {
	return FormatAsk(
		"Elevated privileges",
		fmt.Sprintf("This runs with sudo. `%s`", TruncateCmd(cmd)),
		"Approve to proceed.",
	)
}

func FormatAskSirSelf(cmd string) string {
	return FormatAsk(
		"sir self-modification",
		fmt.Sprintf("This command modifies sir itself. `%s`", TruncateCmd(cmd)),
		"Only you should run sir install/uninstall/clear commands.",
	)
}

func FormatAskDeletePosture(target string) string {
	return FormatAsk(
		fmt.Sprintf("Delete/link security config: %s", target),
		"This is a security configuration file.",
		"Removing or relinking it could disable protections.",
	)
}

func FormatAskMCPUnapproved(toolName string) string {
	return FormatAsk(
		fmt.Sprintf("MCP tool: %s", toolName),
		"This tool comes from a server sir hasn't seen before.",
		"Run `sir trust <server>` to always allow it.",
	)
}

func FormatAskAllowlistedHost(host string) string {
	return FormatAsk(
		fmt.Sprintf("Network request to %s", host),
		"This host is in your security policy but still requires approval.",
		"",
	)
}

func FormatAskPostureElevated(verb, target, posture string, signals []string) string {
	signalList := "none"
	if len(signals) > 0 {
		if len(signals) > 3 {
			signalList = strings.Join(signals[:3], ", ") + fmt.Sprintf(" (+%d more)", len(signals)-3)
		} else {
			signalList = strings.Join(signals, ", ")
		}
	}

	var b strings.Builder
	b.WriteString(colorize(colorBold+colorYellow, "sir: approval needed"))
	b.WriteString(" -- ")
	b.WriteString(target)
	b.WriteString("\n\n")
	b.WriteString("  Why: A previous tool response contained suspicious patterns.\n")
	b.WriteString("       Approving this call is riskier than usual.\n\n")
	b.WriteString("  Signals: ")
	b.WriteString(signalList)
	b.WriteString("\n\n")
	b.WriteString("  Approve to proceed, or deny to block this call.\n\n")
	b.WriteString("  Details: ")
	b.WriteString(colorize(colorDim, "sir explain --last"))
	return b.String()
}
