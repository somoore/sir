package agent

import (
	"fmt"
	"path/filepath"
	"strings"
)

func supportDocPath(m SupportManifest) string {
	switch m.ID {
	case Claude:
		return "docs/user/claude-code-hooks-integration.md"
	case Gemini:
		return "docs/user/gemini-support.md"
	case Codex:
		return "docs/user/codex-support.md"
	default:
		return ""
	}
}

func supportThreatModelDocPath(m SupportManifest) string {
	switch m.ID {
	case Claude:
		return "../user/claude-code-hooks-integration.md"
	case Gemini:
		return "../user/gemini-support.md"
	case Codex:
		return "../user/codex-support.md"
	default:
		return ""
	}
}

func supportRuntimeName(m SupportManifest) string {
	if m.ID == Codex {
		return "codex-cli"
	}
	return m.Name
}

func supportDocLink(m SupportManifest) string {
	path := supportDocPath(m)
	if path == "" {
		return ""
	}
	return fmt.Sprintf("[%s](%s)", filepath.Base(path), path)
}

func supportDocLinkForFAQ(m SupportManifest) string {
	path := supportDocPath(m)
	if path == "" {
		return ""
	}
	base := filepath.Base(path)
	return fmt.Sprintf("[%s](%s)", base, base)
}

func supportLifecycleMitigationDescription(event string) string {
	switch event {
	case "SubagentStart":
		return "SubagentStart delegation gating"
	case "ConfigChange":
		return "ConfigChange tamper detection at the moment of change"
	case "InstructionsLoaded":
		return "InstructionsLoaded pre-read scanning"
	case "Elicitation":
		return "Elicitation interception"
	default:
		return event
	}
}

func formatJoinedItems(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return items[0] + " and " + items[1]
	default:
		return strings.Join(items[:len(items)-1], ", ") + ", and " + items[len(items)-1]
	}
}

func missingLifecycleHooks(m SupportManifest) string {
	return formatJoinedItems(m.UnsupportedSIREvents)
}

func missingLifecycleMitigations(m SupportManifest) string {
	if len(m.UnsupportedSIREvents) == 0 {
		return ""
	}
	items := make([]string, 0, len(m.UnsupportedSIREvents))
	for _, event := range m.UnsupportedSIREvents {
		items = append(items, supportLifecycleMitigationDescription(event))
	}
	return formatJoinedItems(items)
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
		case Gemini, Claude:
			return "SessionEnd closes single-turn blind spots with one last sentinel sweep."
		}
	}
	return ""
}

func supportBlockVerb(spec *AgentSpec) string {
	switch spec.LegacyDenyLiteral {
	case "block", "deny":
		return spec.LegacyDenyLiteral
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

// StatusWarningLine renders the support caveat used by `sir status`.
func (m SupportManifest) StatusWarningLine(agentName string) string {
	switch m.SupportTier {
	case SupportTierNearParity:
		return fmt.Sprintf("             Note: %s is near-parity support; lifecycle coverage remains narrower than Claude Code.\n", agentName)
	case SupportTierLimited:
		return fmt.Sprintf("             Warning: %s remains limited support; enforcement is bounded by the upstream Bash-only hook surface.\n", agentName)
	default:
		return ""
	}
}

// DoctorWarningLine renders the support caveat used by `sir doctor`.
func (m SupportManifest) DoctorWarningLine(agentName string) string {
	switch m.SupportTier {
	case SupportTierNearParity:
		return fmt.Sprintf("  NOTE: %s is near-parity support — file IFC, shell classification, MCP scanning, and credential output scanning are covered, but some lifecycle hooks remain unavailable.\n", agentName)
	case SupportTierLimited:
		return fmt.Sprintf("  WARNING: %s is limited support — Bash-mediated actions are guarded, but native writes and MCP tools still depend on sentinel hashing plus end-of-session sweeps.\n", agentName)
	default:
		return ""
	}
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

func (m SupportManifest) supportOverviewLine() string {
	switch m.SupportTier {
	case SupportTierReference:
		return fmt.Sprintf("- **%s** — **Reference support.** Full %d-hook lifecycle with native interactive approval and complete tool-path coverage.",
			m.Name, m.HookEventCount)
	case SupportTierNearParity:
		if docLink := supportDocLink(m); docLink != "" {
			return fmt.Sprintf("- **%s** — **Near-parity support.** %d hook events fire on %s %s+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: %s. See %s.",
				m.Name, m.HookEventCount, m.Name, m.MinimumVersion, missingLifecycleHooks(m), docLink)
		}
		return fmt.Sprintf("- **%s** — **Near-parity support.** %d hook events fire on %s %s+, with full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: %s.",
			m.Name, m.HookEventCount, m.Name, m.MinimumVersion, missingLifecycleHooks(m))
	case SupportTierLimited:
		if docLink := supportDocLink(m); docLink != "" {
			return fmt.Sprintf("- **%s** — **Limited support.** %d hook events fire on `%s` %s+ after enabling the `%s` feature flag (`%s`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop. See %s.",
				m.Name, m.HookEventCount, supportRuntimeName(m), m.MinimumVersion, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand, docLink)
		}
		return fmt.Sprintf("- **%s** — **Limited support.** %d hook events fire on `%s` %s+ after enabling the `%s` feature flag (`%s`), and the upstream hook surface is Bash-only. Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools stay outside PreToolUse; sir relies on sentinel hashing plus a final `Stop` sweep as the backstop.",
			m.Name, m.HookEventCount, supportRuntimeName(m), m.MinimumVersion, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand)
	default:
		return fmt.Sprintf("- **%s** — **%s.** %d hook events fire.", m.Name, strings.Title(m.TierLabel()), m.HookEventCount)
	}
}

func (m SupportManifest) faqLine() string {
	switch m.SupportTier {
	case SupportTierReference:
		parts := make([]string, 0, 5)
		if m.surface(SurfaceInteractiveApproval).Supported {
			parts = append(parts, "native interactive approval")
		}
		if m.surface(SurfaceMCPToolHooks).Supported {
			parts = append(parts, "MCP scanning")
		}
		if m.surface(SurfaceSubagentStart).Supported {
			parts = append(parts, "delegation gating")
		}
		if m.surface(SurfaceConfigChange).Supported {
			parts = append(parts, "config change detection")
		}
		if m.surface(SurfaceElicitation).Supported {
			parts = append(parts, "elicitation coverage")
		}
		return fmt.Sprintf("- **%s:** %d hook events — reference support with %s.", m.Name, m.HookEventCount, formatJoinedItems(parts))
	case SupportTierNearParity:
		if docLink := supportDocLinkForFAQ(m); docLink != "" {
			return fmt.Sprintf("- **%s %s+:** %d hook events — near-parity support for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: %s. See %s.", m.Name, m.MinimumVersion, m.HookEventCount, missingLifecycleHooks(m), docLink)
		}
		return fmt.Sprintf("- **%s %s+:** %d hook events — near-parity support for file IFC labeling, shell classification, MCP scanning, and credential output scanning. Missing lifecycle hooks: %s.", m.Name, m.MinimumVersion, m.HookEventCount, missingLifecycleHooks(m))
	case SupportTierLimited:
		if docLink := supportDocLinkForFAQ(m); docLink != "" {
			return fmt.Sprintf("- **%s %s+:** %d hook events — limited support with a **Bash-only** upstream hook surface. Requires enabling `%s` (`%s`). Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools still bypass PreToolUse; sir relies on PostToolUse sentinel hashing plus a final `Stop` sweep as the backstop. See %s.", m.Name, m.MinimumVersion, m.HookEventCount, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand, docLink)
		}
		return fmt.Sprintf("- **%s %s+:** %d hook events — limited support with a **Bash-only** upstream hook surface. Requires enabling `%s` (`%s`). Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools still bypass PreToolUse; sir relies on PostToolUse sentinel hashing plus a final `Stop` sweep as the backstop.", m.Name, m.MinimumVersion, m.HookEventCount, m.RequiredFeatureFlag, m.FeatureFlagEnableCommand)
	default:
		return fmt.Sprintf("- **%s:** %d hook events — %s.", m.Name, m.HookEventCount, m.TierLabel())
	}
}

func (m SupportManifest) featureFlagRow() string {
	if m.RequiredFeatureFlag == "" {
		return ""
	}
	return fmt.Sprintf("| Feature flag | ⚠ Required | Enable `%s` before any registered hooks can fire. |\n",
		m.RequiredFeatureFlag)
}

func renderSupportMatrixTable(m SupportManifest, includeFeatureFlag bool) string {
	var b strings.Builder
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
	if includeFeatureFlag {
		if row := m.featureFlagRow(); row != "" {
			b.WriteString(row)
		}
	}
	for _, surface := range m.Surfaces {
		status := "❌ No"
		if surface.Supported {
			status = "✅ Yes"
		}
		b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", surface.Title, status, surface.Notes))
	}
	return strings.TrimRight(b.String(), "\n")
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
	b.WriteString(renderSupportMatrixTable(m, true))
	return strings.TrimRight(b.String(), "\n")
}

// RenderClaudeSupportMatrixBlock renders the generated Claude-specific support
// matrix used by the hooks integration doc.
func RenderClaudeSupportMatrixBlock() string {
	m, ok := SupportManifestForID(Claude)
	if !ok {
		return ""
	}
	return renderSupportMatrixTable(m, false)
}

// RenderReadmeSupportBlock renders the generated support bullets for README.
func RenderReadmeSupportBlock() string {
	lines := make([]string, 0, len(orderedPublicSupportManifests()))
	for _, manifest := range orderedPublicSupportManifests() {
		lines = append(lines, manifest.supportOverviewLine())
	}
	return strings.Join(lines, "\n")
}

func renderFAQLine(m SupportManifest) string {
	return m.faqLine()
}

// RenderFAQSupportBlock renders the generated support block for docs/user/faq.md.
func RenderFAQSupportBlock() string {
	manifests := orderedPublicSupportManifests()
	lines := []string{
		"Claude Code has **reference support**, Gemini CLI has **near-parity support**, and Codex has **limited support** today. `sir install` auto-detects the supported agents already present on this machine, or you can pin one with `sir install --agent <id>`:",
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
	gemini, _ := SupportManifestForID(Gemini)
	codex, _ := SupportManifestForID(Codex)
	return fmt.Sprintf("**Scope note.** The threat model is written primarily against %s because %s is the **reference-support** target: it has the richest hook surface (%d events), native interactive approval, and the most complete sir coverage. %s has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but four Claude-specific lifecycle mitigations are not available: %s. %s has **limited support** with a Bash-only hook surface: Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools bypass PreToolUse, so sir relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [%s](%s) and [%s](%s) for the per-agent coverage matrices.",
		claude.Name,
		claude.Name,
		claude.HookEventCount,
		gemini.Name,
		missingLifecycleMitigations(gemini),
		codex.Name,
		supportThreatModelDocPath(codex),
		supportThreatModelDocPath(codex),
		supportThreatModelDocPath(gemini),
		supportThreatModelDocPath(gemini),
	)
}
