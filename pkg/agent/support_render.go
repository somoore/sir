package agent

import (
	"fmt"
	"strings"
)

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
	return fmt.Sprintf("**Scope note.** The threat model is written primarily against Claude Code because Claude Code is the **reference-support** target: it has the richest hook surface (%d events), native interactive approval, and the most complete sir coverage. Gemini CLI has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but four Claude-specific lifecycle mitigations are not available: SubagentStart delegation gating, ConfigChange tamper detection at the moment of change, InstructionsLoaded pre-read scanning, and Elicitation interception. Codex has **limited support** with a Bash-only hook surface: Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools bypass PreToolUse, so sir relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [../user/codex-support.md](../user/codex-support.md) and [../user/gemini-support.md](../user/gemini-support.md) for the per-agent coverage matrices.", claude.HookEventCount)
}
