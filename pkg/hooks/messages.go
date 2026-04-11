// Package hooks exposes the public user-facing message helpers while the
// rendering logic lives in pkg/hooks/messages. These identifiers are thin
// aliases kept in place so existing call sites inside pkg/hooks (and a few
// external consumers in cmd/sir) continue to compile against the stable
// hooks.Format* surface. Prefer the messages package directly in new code.
package hooks

import hookmessages "github.com/somoore/sir/pkg/hooks/messages"

// Agent-display helper.
var AgentDisplayName = hookmessages.AgentDisplayName

// Core renderers.
var (
	FormatBlock        = hookmessages.FormatBlock
	FormatAsk          = hookmessages.FormatAsk
	FormatAskSensitive = hookmessages.FormatAskSensitive
	FormatFatal        = hookmessages.FormatFatal
	FormatDenyAll      = hookmessages.FormatDenyAll
)

// Hook posture and session lifecycle.
var (
	FormatHookTamper            = hookmessages.FormatHookTamper
	FormatPostureRestore        = hookmessages.FormatPostureRestore
	FormatSessionCleared        = hookmessages.FormatSessionCleared
	FormatInstallPreview        = hookmessages.FormatInstallPreview
	FormatLeaseIntegrityFatal   = hookmessages.FormatLeaseIntegrityFatal
	FormatSessionIntegrityFatal = hookmessages.FormatSessionIntegrityFatal
)

// MCP defense.
var (
	FormatDenyMCPCredential   = hookmessages.FormatDenyMCPCredential
	FormatMCPInjectionWarning = hookmessages.FormatMCPInjectionWarning
	FormatElicitationWarning  = hookmessages.FormatElicitationWarning
)

// Per-verb ask messages.
var (
	FormatAskInstall         = hookmessages.FormatAskInstall
	FormatAskPosture         = hookmessages.FormatAskPosture
	FormatAskEnvRead         = hookmessages.FormatAskEnvRead
	FormatAskEphemeral       = hookmessages.FormatAskEphemeral
	FormatAskPersistence     = hookmessages.FormatAskPersistence
	FormatAskSudo            = hookmessages.FormatAskSudo
	FormatAskSirSelf         = hookmessages.FormatAskSirSelf
	FormatAskDeletePosture   = hookmessages.FormatAskDeletePosture
	FormatAskMCPUnapproved   = hookmessages.FormatAskMCPUnapproved
	FormatAskAllowlistedHost = hookmessages.FormatAskAllowlistedHost
	FormatAskPostureElevated = hookmessages.FormatAskPostureElevated
)

// Per-verb block messages.
var (
	FormatBlockNetExternal = hookmessages.FormatBlockNetExternal
	FormatBlockEgress      = hookmessages.FormatBlockEgress
	FormatBlockPush        = hookmessages.FormatBlockPush
	FormatBlockDelegation  = hookmessages.FormatBlockDelegation
	FormatBlockDNS         = hookmessages.FormatBlockDNS
)
