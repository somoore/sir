// Package agent — AgentSpec is the pure data declaration for an adapter.
//
// Design principle: an adapter is 95% data (tool name maps, event name maps,
// hook registrations, flavor flags) + 5% behavior (three narrow customization
// points). Instead of virtual method dispatch (which Go does not have across
// struct embedding — see the "Go embedding trap" in the refactor plan),
// customization is expressed as function pointer fields on AgentSpec.
//
// The shared implementation in base.go reads the spec and dispatches through
// the function pointers when non-nil, falling back to a sensible default
// otherwise. Adapters are plain data + a thin wrapping struct.
package agent

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// SupportTier is the coarse-grained support posture sir exposes for a host
// agent. This lets docs and status surfaces consume typed adapter metadata
// instead of inferring coverage from prose.
type SupportTier string

const (
	SupportTierReference  SupportTier = "reference"
	SupportTierNearParity SupportTier = "near_parity"
	SupportTierLimited    SupportTier = "limited"
)

// ToolCoverage describes how much of an agent's tool surface sir can
// currently mediate.
type ToolCoverage string

const (
	ToolCoverageFull     ToolCoverage = "full"
	ToolCoverageBashOnly ToolCoverage = "bash_only"
)

// ConfigLayout describes the on-disk representation of each hook event block
// inside the managed config subtree.
type ConfigLayout string

const (
	// ConfigLayoutMatcherGroups is the Claude/Codex/Gemini shape:
	// event -> [{ matcher?, hooks: [{ type, command, timeout }] }].
	ConfigLayoutMatcherGroups ConfigLayout = "matcher_groups"
)

// AgentCapabilities declares the major enforcement surfaces an adapter
// exposes to sir. New adapters must populate this explicitly so support
// claims remain machine-readable.
type AgentCapabilities struct {
	SupportTier          SupportTier
	ToolCoverage         ToolCoverage
	InteractiveApproval  bool
	PostureBackstop      bool
	FileReadIFC          bool
	FileWriteIFC         bool
	ShellClassification  bool
	MCPToolHooks         bool
	SessionTerminalSweep bool

	PreToolUse         bool
	PostToolUse        bool
	UserPromptSubmit   bool
	SubagentStart      bool
	SessionStart       bool
	ConfigChange       bool
	InstructionsLoaded bool
	Stop               bool
	SessionEnd         bool
	Elicitation        bool
}

// SupportsEvent reports whether the capability model says this adapter
// supports the given sir-internal event.
func (c AgentCapabilities) SupportsEvent(event string) bool {
	switch event {
	case "PreToolUse":
		return c.PreToolUse
	case "PostToolUse":
		return c.PostToolUse
	case "UserPromptSubmit":
		return c.UserPromptSubmit
	case "SubagentStart":
		return c.SubagentStart
	case "SessionStart":
		return c.SessionStart
	case "ConfigChange":
		return c.ConfigChange
	case "InstructionsLoaded":
		return c.InstructionsLoaded
	case "Stop":
		return c.Stop
	case "SessionEnd":
		return c.SessionEnd
	case "Elicitation":
		return c.Elicitation
	default:
		return false
	}
}

// StatusSuffix returns any capability-driven caveat that should be surfaced
// next to the hook-registration count in status/doctor output.
func (c AgentCapabilities) StatusSuffix() string {
	parts := []string{}
	switch c.SupportTier {
	case SupportTierReference:
		parts = append(parts, "reference support")
	case SupportTierNearParity:
		parts = append(parts, "near-parity support")
	case SupportTierLimited:
		parts = append(parts, "limited support")
	}
	if c.ToolCoverage == ToolCoverageBashOnly {
		parts = append(parts, "Bash-only")
	}
	if len(parts) == 0 {
		return ""
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

// ConfigStrategy describes how sir should install, canonicalize, compare, and
// restore the agent-managed security subtree in the host config file.
type ConfigStrategy struct {
	// ManagedSubtreeKey is the top-level key under which the hooks map lives
	// in the host config file. Empty means the entire document is itself the
	// managed hook-event map, with no unrelated top-level fields.
	ManagedSubtreeKey string
	// Layout declares how hook entries are represented inside the managed
	// subtree, so install/status/schema paths do not hardcode a single shape.
	Layout ConfigLayout
	// CanonicalBackupFile is the filename sir writes under ~/.sir/ for this
	// agent's canonical managed subtree backup.
	CanonicalBackupFile string
}

// CanonicalBackupPath returns the absolute ~/.sir/ path for this strategy.
func (c ConfigStrategy) CanonicalBackupPath(homeDir string) string {
	return filepath.Join(homeDir, ".sir", c.CanonicalBackupFile)
}

// EffectiveLayout returns the declared layout, defaulting to the current
// matcher-group shape for legacy/manual test construction.
func (c ConfigStrategy) EffectiveLayout() ConfigLayout {
	if c.Layout == "" {
		return ConfigLayoutMatcherGroups
	}
	return c.Layout
}

// ResponseFormat selects how PreToolUse/PostToolUse verdicts are formatted.
type ResponseFormat int

const (
	// ResponseFormatClaude emits the hookSpecificOutput envelope with
	// permissionDecision. Used by Claude Code.
	ResponseFormatClaude ResponseFormat = iota
	// ResponseFormatLegacy emits the flat { decision, reason } object
	// (Codex uses "block", Gemini uses "deny" — the literal is
	// controlled by Spec.LegacyDenyLiteral).
	ResponseFormatLegacy
)

// HookRegistration describes a single hook event to wire into the agent's
// settings file. The base GenerateHooksConfigMap walks Spec.HookRegistrations
// and builds the nested map shape the agent expects.
type HookRegistration struct {
	// Event is the sir-internal event name (e.g. "PreToolUse"). The
	// base layer translates this to the agent's native wire name via
	// reverse-lookup of Spec.EventNames when emitting the config.
	Event string
	// Matcher is the tool-name matcher expression. Empty means the hook
	// is non-tool-scoped (no "matcher" field in the emitted entry).
	Matcher string
	// Command is the trailing CLI subcommand that sir runs for this hook
	// (e.g. "guard evaluate"). The agent-specific --agent flag is added
	// automatically from Spec.CommandFlag.
	Command string
	// Timeout is the hook timeout expressed in Spec.TimeoutUnit (seconds
	// for Claude/Codex, milliseconds for Gemini).
	Timeout int
}

// AgentSpec is the pure data declaration for an adapter.
type AgentSpec struct {
	// Identity --------------------------------------------------------

	ID                  AgentID
	Name                string
	MinVersion          string
	Capabilities        AgentCapabilities
	SupportedSIREvents  []string // sir-internal event names in display order
	SupportedWireEvents []string // agent-native event names (for SupportedEvents() API)

	// Installation detection -----------------------------------------

	// ConfigFile is the relative path under $HOME to the agent's
	// settings file (e.g. ".claude/settings.json").
	ConfigFile string
	// ConfigDirs are directories relative to $HOME whose existence is
	// a positive install signal (e.g. ".claude", ".codex").
	ConfigDirs []string
	// BinaryNames are binary names whose presence on $PATH is a
	// positive install signal (e.g. "codex", "gemini"). Claude leaves
	// this empty because it uses the config-dir signal instead.
	BinaryNames []string
	// RuntimeProxyHosts are the minimal provider/API endpoints sir should
	// pre-authorize when `sir run` launches this host agent behind the
	// local egress proxy. Developers can extend this set with approved_hosts
	// in the lease or ad-hoc --allow-host flags.
	RuntimeProxyHosts []string
	// RequiredFeatureFlag is a host-agent feature gate that must be enabled
	// before sir's registered hooks will actually fire.
	RequiredFeatureFlag string
	// FeatureFlagEnableCommand is the user-facing command to enable the
	// required feature flag, when one exists.
	FeatureFlagEnableCommand string

	// Naming translation ---------------------------------------------

	// ToolNames maps the agent's native tool name to sir's internal
	// name (which matches Claude Code's). Missing entries pass through
	// unchanged.
	ToolNames map[string]string
	// EventNames maps the agent's native hook event name to sir's
	// internal name (e.g. "BeforeTool" -> "PreToolUse"). Missing
	// entries pass through unchanged. Used bidirectionally: parse
	// direction (native -> internal) and config emission direction
	// (internal -> native via reverse lookup).
	EventNames map[string]string
	// MCPPrefix, if non-empty, is the prefix that marks an MCP tool
	// name in the agent's native naming (e.g. "mcp_" for Gemini). The
	// base normalizer rewrites "<prefix><server><sep><tool>" into
	// sir's "mcp__<server>__<tool>" form using the first occurrence
	// of MCPSeparator after the prefix.
	MCPPrefix    string
	MCPSeparator string

	// Response formatting --------------------------------------------

	ResponseFormat ResponseFormat
	// HasAskVerdict is true for agents that distinguish "ask" from
	// "deny" in their wire contract. When false, the legacy formatter
	// folds "ask" into a deny with AskToDenySuffix appended.
	HasAskVerdict bool
	// LegacyDenyLiteral is the decision string used by the legacy
	// formatter for non-allow verdicts ("block" for Codex, "deny"
	// for Gemini).
	LegacyDenyLiteral string
	// EmitLegacyPostEnvelope controls whether the legacy PostToolUse
	// formatter includes the Claude-style hookSpecificOutput envelope
	// alongside the top-level { decision, reason } fields. Codex
	// emits it; Gemini does not.
	EmitLegacyPostEnvelope bool

	// Hook config emission --------------------------------------------

	// ConfigStrategy defines where sir's managed subtree lives in the host
	// config document and where the canonical backup is stored under ~/.sir/.
	ConfigStrategy ConfigStrategy
	// TimeoutUnit documents the unit of HookRegistration.Timeout.
	// Used only for self-documentation; the base emitter just passes
	// the integer through.
	TimeoutUnit string
	// HookRegistrations is the ordered list of hook events to emit in
	// the config. Order does not affect JSON output (Go sorts map
	// keys lexicographically on marshal), but documentation order
	// matters when reading the spec.
	HookRegistrations []HookRegistration
	// CommandFlag is the "--agent xxx" suffix appended to every hook
	// command in the emitted config. Empty for Claude (no flag needed
	// since Claude is the default).
	CommandFlag string

	// Customization points -------------------------------------------
	//
	// These are function pointer fields, NOT methods. Go struct
	// embedding does not provide virtual dispatch, so a "method
	// override" on the outer agent type would silently never fire
	// when invoked via the embedded BaseAgent. Function pointers on
	// the spec make dispatch explicit and correct.

	// ExtractToolOutputFunc, if set, flattens an agent-specific
	// structured tool_response payload into a plain string for
	// downstream scanners. Used by Gemini (llmContent / returnDisplay
	// extraction). Codex has a one-line fallback that Claude does not
	// need, so it is handled directly in the base parser.
	ExtractToolOutputFunc func(raw json.RawMessage) string

	// FormatLifecycleFunc, if set, is called for lifecycle events
	// (SessionStart, Stop, etc.) instead of the legacy formatter.
	// Used by Claude because its lifecycle shape is entirely
	// different from the legacy shape.
	FormatLifecycleFunc func(eventName, decision, reason, context string) ([]byte, error)

	// PostInstallFunc, if set, runs after the agent's hook config has
	// been written. Used by Codex to ensure the codex_hooks feature
	// flag is enabled in ~/.codex/config.toml. Wired in cmd/sir
	// (which owns the ensureCodexFeatureFlag implementation) to
	// avoid a pkg/agent → cmd/sir circular dependency.
	PostInstallFunc func(homeDir string, skipPrompt bool)
}
