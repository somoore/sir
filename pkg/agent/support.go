package agent

import (
	"fmt"
	"strings"
)

// SupportSurfaceKey identifies one concrete security surface in the public
// support manifest.
type SupportSurfaceKey string

const (
	SurfaceInteractiveApproval SupportSurfaceKey = "interactive_approval"
	SurfaceFileReadIFC         SupportSurfaceKey = "file_read_ifc"
	SurfaceFileWriteIFC        SupportSurfaceKey = "file_write_ifc"
	SurfaceShellClassification SupportSurfaceKey = "shell_classification"
	SurfaceMCPToolHooks        SupportSurfaceKey = "mcp_tool_hooks"
	SurfaceSubagentStart       SupportSurfaceKey = "subagent_start"
	SurfaceConfigChange        SupportSurfaceKey = "config_change"
	SurfaceInstructionsLoaded  SupportSurfaceKey = "instructions_loaded"
	SurfaceElicitation         SupportSurfaceKey = "elicitation"
	SurfaceSessionSweep        SupportSurfaceKey = "session_terminal_sweep"
)

var allSIREvents = []string{
	"PreToolUse",
	"PostToolUse",
	"UserPromptSubmit",
	"SubagentStart",
	"SessionStart",
	"ConfigChange",
	"InstructionsLoaded",
	"Stop",
	"SessionEnd",
	"Elicitation",
}

// SupportSurface is one machine-readable support claim.
type SupportSurface struct {
	Key       SupportSurfaceKey `json:"key"`
	Title     string            `json:"title"`
	Supported bool              `json:"supported"`
	Notes     string            `json:"notes,omitempty"`
}

// SupportManifest is the machine-readable summary of an adapter's support
// posture. Public docs and CLI status output are rendered from this shape.
type SupportManifest struct {
	ID                       AgentID          `json:"id"`
	Name                     string           `json:"name"`
	MinimumVersion           string           `json:"minimum_version,omitempty"`
	SupportTier              SupportTier      `json:"support_tier"`
	ToolCoverage             ToolCoverage     `json:"tool_coverage"`
	HookEventCount           int              `json:"hook_event_count"`
	SupportedSIREvents       []string         `json:"supported_sir_events"`
	UnsupportedSIREvents     []string         `json:"unsupported_sir_events,omitempty"`
	SupportedWireEvents      []string         `json:"supported_wire_events"`
	RequiredFeatureFlag      string           `json:"required_feature_flag,omitempty"`
	FeatureFlagEnableCommand string           `json:"feature_flag_enable_command,omitempty"`
	Surfaces                 []SupportSurface `json:"surfaces"`
}

// AllSIREvents returns the canonical sir-internal event list in display order.
func AllSIREvents() []string {
	out := make([]string, len(allSIREvents))
	copy(out, allSIREvents)
	return out
}

// AllSupportManifests returns the public support manifest for every adapter.
func AllSupportManifests() []SupportManifest {
	regs := Registry()
	out := make([]SupportManifest, 0, len(regs))
	for _, reg := range regs {
		out = append(out, SupportManifestForSpec(reg.Spec))
	}
	return out
}

func orderedPublicSupportManifests() []SupportManifest {
	order := []AgentID{Claude, Gemini, Codex}
	out := make([]SupportManifest, 0, len(order))
	for _, id := range order {
		if manifest, ok := SupportManifestForID(id); ok {
			out = append(out, manifest)
		}
	}
	return out
}

// SupportManifestForID returns the public support manifest for one adapter.
func SupportManifestForID(id AgentID) (SupportManifest, bool) {
	for _, reg := range Registry() {
		if reg.ID == id {
			return SupportManifestForSpec(reg.Spec), true
		}
	}
	return SupportManifest{}, false
}

// SupportManifestForAgent builds the support manifest for an adapter.
func SupportManifestForAgent(ag Agent) SupportManifest {
	return SupportManifestForSpec(ag.GetSpec())
}

// SupportManifestForSpec builds the support manifest for an adapter spec.
func SupportManifestForSpec(spec *AgentSpec) SupportManifest {
	if spec == nil {
		return SupportManifest{}
	}
	supportedSIREvents := derivedSupportedSIREvents(spec)
	supportedWireEvents := derivedSupportedWireEvents(spec, supportedSIREvents)
	unsupported := unsupportedSIREvents(spec, supportedSIREvents)
	return SupportManifest{
		ID:                       spec.ID,
		Name:                     spec.Name,
		MinimumVersion:           spec.MinVersion,
		SupportTier:              spec.Capabilities.SupportTier,
		ToolCoverage:             spec.Capabilities.ToolCoverage,
		HookEventCount:           len(supportedSIREvents),
		SupportedSIREvents:       supportedSIREvents,
		UnsupportedSIREvents:     unsupported,
		SupportedWireEvents:      supportedWireEvents,
		RequiredFeatureFlag:      spec.RequiredFeatureFlag,
		FeatureFlagEnableCommand: spec.FeatureFlagEnableCommand,
		Surfaces: []SupportSurface{
			{
				Key:       SurfaceInteractiveApproval,
				Title:     "Interactive approvals",
				Supported: spec.Capabilities.InteractiveApproval,
				Notes:     supportSurfaceNotes(spec, SurfaceInteractiveApproval),
			},
			{
				Key:       SurfaceFileReadIFC,
				Title:     "File-read IFC labeling",
				Supported: spec.Capabilities.FileReadIFC,
				Notes:     supportSurfaceNotes(spec, SurfaceFileReadIFC),
			},
			{
				Key:       SurfaceFileWriteIFC,
				Title:     "File-write pre-gating",
				Supported: spec.Capabilities.FileWriteIFC,
				Notes:     supportSurfaceNotes(spec, SurfaceFileWriteIFC),
			},
			{
				Key:       SurfaceShellClassification,
				Title:     "Shell classification",
				Supported: spec.Capabilities.ShellClassification,
				Notes:     supportSurfaceNotes(spec, SurfaceShellClassification),
			},
			{
				Key:       SurfaceMCPToolHooks,
				Title:     "MCP tool hooks",
				Supported: spec.Capabilities.MCPToolHooks,
				Notes:     supportSurfaceNotes(spec, SurfaceMCPToolHooks),
			},
			{
				Key:       SurfaceSubagentStart,
				Title:     "Delegation gating",
				Supported: spec.Capabilities.SubagentStart,
				Notes:     supportSurfaceNotes(spec, SurfaceSubagentStart),
			},
			{
				Key:       SurfaceConfigChange,
				Title:     "Config change detection",
				Supported: spec.Capabilities.ConfigChange,
				Notes:     supportSurfaceNotes(spec, SurfaceConfigChange),
			},
			{
				Key:       SurfaceInstructionsLoaded,
				Title:     "InstructionsLoaded scanning",
				Supported: spec.Capabilities.InstructionsLoaded,
				Notes:     supportSurfaceNotes(spec, SurfaceInstructionsLoaded),
			},
			{
				Key:       SurfaceElicitation,
				Title:     "Elicitation interception",
				Supported: spec.Capabilities.Elicitation,
				Notes:     supportSurfaceNotes(spec, SurfaceElicitation),
			},
			{
				Key:       SurfaceSessionSweep,
				Title:     "Terminal posture sweep",
				Supported: spec.Capabilities.SessionTerminalSweep,
				Notes:     supportSurfaceNotes(spec, SurfaceSessionSweep),
			},
		},
	}
}

func derivedSupportedSIREvents(spec *AgentSpec) []string {
	if spec == nil {
		return nil
	}
	out := make([]string, 0, len(allSIREvents))
	seen := make(map[string]struct{}, len(allSIREvents))
	for _, event := range spec.SupportedSIREvents {
		if !spec.Capabilities.SupportsEvent(event) {
			continue
		}
		out = append(out, event)
		seen[event] = struct{}{}
	}
	for _, event := range allSIREvents {
		if spec.Capabilities.SupportsEvent(event) {
			if _, ok := seen[event]; ok {
				continue
			}
			out = append(out, event)
		}
	}
	return out
}

func unsupportedSIREvents(spec *AgentSpec, supported []string) []string {
	if spec == nil {
		return nil
	}
	supportedSet := make(map[string]struct{}, len(supported))
	for _, event := range supported {
		supportedSet[event] = struct{}{}
	}
	out := make([]string, 0, len(allSIREvents)-len(supported))
	for _, event := range allSIREvents {
		if _, ok := supportedSet[event]; ok {
			continue
		}
		out = append(out, event)
	}
	return out
}

func derivedSupportedWireEvents(spec *AgentSpec, supported []string) []string {
	if spec == nil {
		return nil
	}
	out := make([]string, 0, len(supported))
	for _, event := range supported {
		out = append(out, wireEventNameForSpec(spec, event))
	}
	return out
}

func wireEventNameForSpec(spec *AgentSpec, sirEvent string) string {
	if spec == nil {
		return sirEvent
	}
	for native, internal := range spec.EventNames {
		if internal == sirEvent {
			return native
		}
	}
	return sirEvent
}

// ValidateSupportContract ensures the hand-maintained support metadata on an
// adapter spec still matches the capability model and registered hooks.
func ValidateSupportContract(spec *AgentSpec) error {
	if spec == nil {
		return nil
	}
	problems := make([]string, 0, 4)

	expectedSIREvents := derivedSupportedSIREvents(spec)
	if !equalStringSlices(spec.SupportedSIREvents, expectedSIREvents) {
		problems = append(problems, fmt.Sprintf("supported sir events drift: got %v want %v", spec.SupportedSIREvents, expectedSIREvents))
	}

	expectedWireEvents := derivedSupportedWireEvents(spec, expectedSIREvents)
	if !equalStringSlices(spec.SupportedWireEvents, expectedWireEvents) {
		problems = append(problems, fmt.Sprintf("supported wire events drift: got %v want %v", spec.SupportedWireEvents, expectedWireEvents))
	}

	for _, registration := range spec.HookRegistrations {
		if !spec.Capabilities.SupportsEvent(registration.Event) {
			problems = append(problems, fmt.Sprintf("hook registration %q is not declared supported in capabilities", registration.Event))
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf(strings.Join(problems, "; "))
	}
	return nil
}

func equalStringSlices(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func cloneStrings(in []string) []string {
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func supportSurfaceNotes(spec *AgentSpec, key SupportSurfaceKey) string {
	switch key {
	case SurfaceInteractiveApproval:
		if spec.Capabilities.InteractiveApproval {
			return "Native ask/allow/deny responses are preserved."
		}
		return fmt.Sprintf("%s folds sir's internal ask verdict into %s with remediation text.",
			spec.Name, supportBlockVerb(spec))
	case SurfaceFileReadIFC:
		switch spec.ID {
		case Claude:
			return "Sensitive reads are labeled before execution via Claude's native Read/Edit hook path."
		case Gemini:
			return "BeforeTool labels read_file/read_many_files before execution."
		case Codex:
			return "Bash-mediated sensitive reads (cat/sed/head/tail/grep/etc.) are promoted to read_ref before execution."
		}
	case SurfaceFileWriteIFC:
		switch spec.ID {
		case Claude:
			return "Write/Edit posture changes are gated before the write executes."
		case Gemini:
			return "BeforeTool gates write_file / replace posture mutations before execution."
		case Codex:
			return "Native apply_patch writes bypass PreToolUse on codex-cli 0.118.x; posture tamper is caught post-hoc."
		}
	case SurfaceShellClassification:
		switch spec.Capabilities.ToolCoverage {
		case ToolCoverageBashOnly:
			return "Every hooked Codex tool call is Bash, so sir's shell classifier is the primary enforcement path."
		default:
			return "Bash commands are classified for egress, DNS, persistence, sudo, and install risk."
		}
	case SurfaceMCPToolHooks:
		if spec.Capabilities.MCPToolHooks {
			return "sir sees both MCP arguments and MCP responses on this agent."
		}
		return fmt.Sprintf("%s does not fire hooks for MCP tools today.", spec.Name)
	case SurfaceSubagentStart:
		if spec.Capabilities.SubagentStart {
			return "Delegation policy is enforced at SubagentStart."
		}
		return fmt.Sprintf("%s exposes no SubagentStart-equivalent hook.", spec.Name)
	case SurfaceConfigChange:
		if spec.Capabilities.ConfigChange {
			return "Mid-session hook config edits are detected when they happen."
		}
		return fmt.Sprintf("%s exposes no ConfigChange-equivalent hook.", spec.Name)
	case SurfaceInstructionsLoaded:
		if spec.Capabilities.InstructionsLoaded {
			return "Context files are scanned when the agent loads them."
		}
		return fmt.Sprintf("%s exposes no InstructionsLoaded-equivalent hook.", spec.Name)
	case SurfaceElicitation:
		if spec.Capabilities.Elicitation {
			return "Developer-facing permission prompts are scanned before display."
		}
		return fmt.Sprintf("%s exposes no Elicitation-equivalent hook.", spec.Name)
	case SurfaceSessionSweep:
		switch spec.ID {
		case Codex:
			return "The final posture sweep runs on Stop because Codex exposes no SessionEnd hook."
		case Gemini:
			return "SessionEnd closes single-turn blind spots with one last sentinel sweep."
		case Claude:
			return "SessionEnd closes single-turn blind spots with one last sentinel sweep."
		}
	}
	return ""
}

func supportBlockVerb(spec *AgentSpec) string {
	switch spec.LegacyDenyLiteral {
	case "block":
		return "block"
	case "deny":
		return "deny"
	default:
		return "deny"
	}
}

func (m SupportManifest) TierLabel() string {
	switch m.SupportTier {
	case SupportTierReference:
		return "reference support"
	case SupportTierNearParity:
		return "near-parity support"
	case SupportTierLimited:
		return "limited support"
	default:
		return string(m.SupportTier)
	}
}

// StatusSuffix is the capability-driven caveat shown in status/doctor output.
func (m SupportManifest) StatusSuffix() string {
	parts := []string{m.TierLabel()}
	if m.ToolCoverage == ToolCoverageBashOnly {
		parts = append(parts, "Bash-only")
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

// StatusHeading is the generated heading used by per-agent support docs.
func (m SupportManifest) StatusHeading() string {
	switch m.ID {
	case Gemini:
		return fmt.Sprintf("## Status: near-parity support on Gemini CLI %s+", m.MinimumVersion)
	case Codex:
		return fmt.Sprintf("## Status: limited support on codex-cli %s+ (Bash-only)", m.MinimumVersion)
	case Claude:
		return "## Status: reference support on Claude Code"
	default:
		return fmt.Sprintf("## Status: %s on %s", m.TierLabel(), m.Name)
	}
}

func (m SupportManifest) surface(key SupportSurfaceKey) SupportSurface {
	for _, surface := range m.Surfaces {
		if surface.Key == key {
			return surface
		}
	}
	return SupportSurface{Key: key}
}

func (m SupportManifest) featureFlagRow() string {
	if m.RequiredFeatureFlag == "" {
		return ""
	}
	return fmt.Sprintf("| Feature flag | ⚠ Required | Enable `%s` before any registered hooks can fire. |\n",
		m.RequiredFeatureFlag)
}

// RenderSupportDocBlock renders the generated support block for one agent doc.
func RenderSupportDocBlock(id AgentID) string {
	m, ok := SupportManifestForID(id)
	if !ok {
		return ""
	}
	var b strings.Builder
	b.WriteString(m.StatusHeading())
	b.WriteString("\n\n")
	b.WriteString("| Surface | Status | Notes |\n")
	b.WriteString("|---|---|---|\n")
	b.WriteString(fmt.Sprintf("| Hook events wired | ✅ %d events | %s |\n",
		m.HookEventCount, strings.Join(m.SupportedWireEvents, ", ")))
	switch m.ToolCoverage {
	case ToolCoverageBashOnly:
		b.WriteString("| Tool-path coverage | ⚠ Bash-only | Shell classification is enforced, but non-Bash tools bypass sir entirely. |\n")
	default:
		b.WriteString("| Tool-path coverage | ✅ Full | File IFC labeling, shell classification, MCP scanning, and credential output scanning all run on the hooked tool path. |\n")
	}
	if row := m.featureFlagRow(); row != "" {
		b.WriteString(row)
	}
	for _, key := range []SupportSurfaceKey{
		SurfaceInteractiveApproval,
		SurfaceFileReadIFC,
		SurfaceFileWriteIFC,
		SurfaceShellClassification,
		SurfaceMCPToolHooks,
		SurfaceSubagentStart,
		SurfaceConfigChange,
		SurfaceInstructionsLoaded,
		SurfaceElicitation,
		SurfaceSessionSweep,
	} {
		surface := m.surface(key)
		status := "❌ No"
		if surface.Supported {
			status = "✅ Yes"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", surface.Title, status, surface.Notes))
	}
	return strings.TrimRight(b.String(), "\n")
}

func renderSupportOverviewLine(m SupportManifest) string {
	switch m.ID {
	case Claude:
		return fmt.Sprintf("- **Claude Code** — **Reference support.** Full %d-hook lifecycle with native interactive approval and complete tool-path coverage.",
			m.HookEventCount)
	case Gemini:
		return fmt.Sprintf("- **Gemini CLI** — **Near-parity support.** %d hook events fire on Gemini CLI %s+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [docs/user/gemini-support.md](docs/user/gemini-support.md).",
			m.HookEventCount, m.MinimumVersion)
	case Codex:
		return fmt.Sprintf("- **Codex** — **Limited support.** %d hook events fire on `codex-cli` %s+ after enabling the `%s` feature flag (`%s`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See [docs/user/codex-support.md](docs/user/codex-support.md).",
			m.HookEventCount, m.MinimumVersion, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand)
	default:
		return fmt.Sprintf("- **%s** — **%s.** %d hook events fire.", m.Name, strings.Title(m.TierLabel()), m.HookEventCount)
	}
}

// RenderReadmeSupportBlock renders the generated support bullets for README.
func RenderReadmeSupportBlock() string {
	lines := make([]string, 0, len(orderedPublicSupportManifests()))
	for _, manifest := range orderedPublicSupportManifests() {
		lines = append(lines, renderSupportOverviewLine(manifest))
	}
	return strings.Join(lines, "\n")
}

func renderFAQLine(m SupportManifest) string {
	switch m.ID {
	case Claude:
		return fmt.Sprintf("- **Claude Code:** %d hook events — reference support with native interactive approval, MCP scanning, delegation gating, config change detection, and elicitation coverage.", m.HookEventCount)
	case Gemini:
		return fmt.Sprintf("- **Gemini CLI %s+:** %d hook events — near-parity support for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: SubagentStart, ConfigChange, InstructionsLoaded, and Elicitation. See [gemini-support.md](gemini-support.md).", m.MinimumVersion, m.HookEventCount)
	case Codex:
		return fmt.Sprintf("- **Codex %s+:** %d hook events — limited support with a **Bash-only** upstream hook surface. Requires enabling `%s` (`%s`). Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools still bypass PreToolUse; sir relies on PostToolUse sentinel hashing plus a final `Stop` sweep as the backstop. See [codex-support.md](codex-support.md).", m.MinimumVersion, m.HookEventCount, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand)
	default:
		return fmt.Sprintf("- **%s:** %d hook events — %s.", m.Name, m.HookEventCount, m.TierLabel())
	}
}

// RenderFAQSupportBlock renders the generated support block for docs/user/faq.md.
func RenderFAQSupportBlock() string {
	manifests := orderedPublicSupportManifests()
	lines := []string{
		"Claude Code has **reference support**, Gemini CLI has **near-parity support**, and Codex has **limited support** today. `sir install` auto-detects whichever are present and wires up what each agent's hook surface actually supports:",
		"",
	}
	for _, manifest := range manifests {
		lines = append(lines, renderFAQLine(manifest))
	}
	return strings.Join(lines, "\n")
}

// RenderThreatModelScopeBlock renders the generated scope paragraph used by
// the public threat model doc.
func RenderThreatModelScopeBlock() string {
	claude, _ := SupportManifestForID(Claude)
	return fmt.Sprintf("**Scope note.** The threat model is written primarily against Claude Code because Claude Code is the **reference-support** target: it has the richest hook surface (%d events), native interactive approval, and the most complete sir coverage. Gemini CLI has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but four Claude-specific lifecycle mitigations are not available: SubagentStart delegation gating, ConfigChange tamper detection at the moment of change, InstructionsLoaded pre-read scanning, and Elicitation interception. Codex has **limited support** with a Bash-only hook surface: Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools bypass PreToolUse, so sir relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [../user/codex-support.md](../user/codex-support.md) and [../user/gemini-support.md](../user/gemini-support.md) for the per-agent coverage matrices.", claude.HookEventCount)
}
