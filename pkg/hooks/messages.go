// Package hooks exposes the public user-facing message helpers while the
// rendering logic lives in smaller internal seams.
package hooks

import hookmessages "github.com/somoore/sir/pkg/hooks/messages"
import "time"

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

func AgentDisplayName(id string) string {
	return hookmessages.AgentDisplayName(id)
}

func colorsEnabled() bool {
	return hookmessages.ColorsEnabled()
}

func colorize(color, text string) string {
	if !colorsEnabled() {
		return text
	}
	return color + text + colorReset
}

func extractHostForMessage(dest string) (string, bool) {
	return hookmessages.ExtractHostForMessage(dest)
}

func FormatBlock(action, causalChain, fix string) string {
	return hookmessages.FormatBlock(action, causalChain, fix)
}

func FormatAsk(action, reason, consequence string) string {
	return hookmessages.FormatAsk(action, reason, consequence)
}

func FormatAskSensitive(target string, scope string) string {
	return hookmessages.FormatAskSensitive(target, scope)
}

func FormatFatal(action, consequence, remedy string) string {
	return hookmessages.FormatFatal(action, consequence, remedy)
}

func FormatDenyAll(reason string) string {
	return hookmessages.FormatDenyAll(reason)
}

func FormatHookTamper(file string) string {
	return hookmessages.FormatHookTamper(file)
}

func FormatPostureRestore(file string) string {
	return hookmessages.FormatPostureRestore(file)
}

func FormatSessionCleared() string {
	return hookmessages.FormatSessionCleared()
}

func FormatDenyMCPCredential(toolName, serverName, patternHint string) string {
	return hookmessages.FormatDenyMCPCredential(toolName, serverName, patternHint)
}

func FormatMCPInjectionWarning(serverName, severity string, patterns []string) string {
	return hookmessages.FormatMCPInjectionWarning(serverName, severity, patterns)
}

func FormatElicitationWarning(patterns []string) string {
	return hookmessages.FormatElicitationWarning(patterns)
}

func FormatInstallPreview(hooksPath, stateDir, leasePath string, postureFiles []string) string {
	return hookmessages.FormatInstallPreview(hooksPath, stateDir, leasePath, postureFiles)
}

func FormatLeaseIntegrityFatal() string {
	return hookmessages.FormatLeaseIntegrityFatal()
}

func FormatSessionIntegrityFatal() string {
	return hookmessages.FormatSessionIntegrityFatal()
}

func truncateCmd(cmd string) string {
	return hookmessages.TruncateCmd(cmd)
}

func FormatAskInstall(pkgName, manager string) string {
	return hookmessages.FormatAskInstall(pkgName, manager)
}

func FormatAskPosture(target string) string {
	return hookmessages.FormatAskPosture(target)
}

func FormatAskEnvRead(cmd string) string {
	return hookmessages.FormatAskEnvRead(cmd)
}

func FormatAskEphemeral(target string) string {
	return hookmessages.FormatAskEphemeral(target)
}

func FormatAskPersistence(cmd string) string {
	return hookmessages.FormatAskPersistence(cmd)
}

func FormatAskSudo(cmd string) string {
	return hookmessages.FormatAskSudo(cmd)
}

func FormatAskSirSelf(cmd string) string {
	return hookmessages.FormatAskSirSelf(cmd)
}

func FormatAskDeletePosture(target string) string {
	return hookmessages.FormatAskDeletePosture(target)
}

func FormatAskMCPUnapproved(toolName string) string {
	return hookmessages.FormatAskMCPUnapproved(toolName)
}

func FormatAskAllowlistedHost(host string) string {
	return hookmessages.FormatAskAllowlistedHost(host)
}

func FormatAskPostureElevated(verb, target, posture string, signals []string) string {
	return hookmessages.FormatAskPostureElevated(verb, target, posture, signals)
}

func FormatBlockNetExternal(agentName, dest string, secretReadTime time.Time) string {
	return hookmessages.FormatBlockNetExternal(agentName, dest, secretReadTime)
}

func FormatBlockEgress(agentName, dest string, secretReadTime time.Time) string {
	return hookmessages.FormatBlockEgress(agentName, dest, secretReadTime)
}

func FormatBlockPush(agentName, remote string, secretReadTime time.Time) string {
	return hookmessages.FormatBlockPush(agentName, remote, secretReadTime)
}

func FormatBlockDelegation(agentName string) string {
	return hookmessages.FormatBlockDelegation(agentName)
}

func FormatBlockDNS(agentName, target string, secretReadTime time.Time) string {
	return hookmessages.FormatBlockDNS(agentName, target, secretReadTime)
}
