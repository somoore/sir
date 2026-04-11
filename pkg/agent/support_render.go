package agent

import (
	"fmt"
	"path/filepath"
	"strings"
)

// supportRenderProfile holds per-agent rendering metadata. Adding a new agent
// means adding one entry to supportRenderProfiles — no switch edits needed.
// docPath / threatModelDocPath are relative to the README / docs/research/.
// runtimeName overrides the manifest Name in status headings (Codex shows as
// "codex-cli"); empty falls through to Name. statusHeadingTemplate may
// contain one "%s" which is substituted with MinimumVersion. surfaceNotes
// holds per-agent overrides for surfaces whose text is not a pure function
// of Capabilities (FileReadIFC, FileWriteIFC, SessionSweep).
type supportRenderProfile struct {
	docPath               string
	threatModelDocPath    string
	runtimeName           string
	statusHeadingTemplate string
	surfaceNotes          map[SupportSurfaceKey]string
}

var supportRenderProfiles = map[AgentID]supportRenderProfile{
	Claude: {
		docPath:               "docs/user/claude-code-hooks-integration.md",
		threatModelDocPath:    "../user/claude-code-hooks-integration.md",
		statusHeadingTemplate: "## Status: reference support on Claude Code",
		surfaceNotes: map[SupportSurfaceKey]string{
			SurfaceFileReadIFC:  "Sensitive reads are labeled before execution via Claude's native Read/Edit hook path.",
			SurfaceFileWriteIFC: "Write/Edit posture changes are gated before the write executes.",
			SurfaceSessionSweep: "SessionEnd closes single-turn blind spots with one last sentinel sweep.",
		},
	},
	Gemini: {
		docPath:               "docs/user/gemini-support.md",
		threatModelDocPath:    "../user/gemini-support.md",
		statusHeadingTemplate: "## Status: near-parity support on Gemini CLI %s+",
		surfaceNotes: map[SupportSurfaceKey]string{
			SurfaceFileReadIFC:  "BeforeTool labels read_file/read_many_files before execution.",
			SurfaceFileWriteIFC: "BeforeTool gates write_file / replace posture mutations before execution.",
			SurfaceSessionSweep: "SessionEnd closes single-turn blind spots with one last sentinel sweep.",
		},
	},
	Codex: {
		docPath:               "docs/user/codex-support.md",
		threatModelDocPath:    "../user/codex-support.md",
		runtimeName:           "codex-cli",
		statusHeadingTemplate: "## Status: limited support on codex-cli %s+ (Bash-only)",
		surfaceNotes: map[SupportSurfaceKey]string{
			SurfaceFileReadIFC:  "Bash-mediated sensitive reads (cat/sed/head/tail/grep/etc.) are promoted to read_ref before execution.",
			SurfaceFileWriteIFC: "Native apply_patch writes bypass PreToolUse on codex-cli 0.118.x; posture tamper is caught post-hoc.",
			SurfaceSessionSweep: "The final posture sweep runs on Stop because Codex exposes no SessionEnd hook.",
		},
	},
}

func supportDocPath(m SupportManifest) string {
	return supportRenderProfiles[m.ID].docPath
}

func supportThreatModelDocPath(m SupportManifest) string {
	return supportRenderProfiles[m.ID].threatModelDocPath
}

func supportRuntimeName(m SupportManifest) string {
	if name := supportRenderProfiles[m.ID].runtimeName; name != "" {
		return name
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

// lifecycleMitigationDescriptions maps a sir-internal lifecycle event name to
// the human-facing mitigation phrase used in threat model and FAQ prose.
var lifecycleMitigationDescriptions = map[string]string{
	"SubagentStart":      "SubagentStart delegation gating",
	"ConfigChange":       "ConfigChange tamper detection at the moment of change",
	"InstructionsLoaded": "InstructionsLoaded pre-read scanning",
	"Elicitation":        "Elicitation interception",
}

func supportLifecycleMitigationDescription(event string) string {
	if desc, ok := lifecycleMitigationDescriptions[event]; ok {
		return desc
	}
	return event
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

// capabilityBranch describes a surface whose note text is purely a function
// of a per-agent Capability bool. The unsupported template may contain one
// "%s" for the agent name.
type capabilityBranch struct {
	capability  func(AgentCapabilities) bool
	supported   string
	unsupported string // format string, "%s" = spec.Name
}

var capabilityBranchNotes = map[SupportSurfaceKey]capabilityBranch{
	SurfaceMCPToolHooks: {
		capability:  func(c AgentCapabilities) bool { return c.MCPToolHooks },
		supported:   "sir sees both MCP arguments and MCP responses on this agent.",
		unsupported: "%s does not fire hooks for MCP tools today.",
	},
	SurfaceSubagentStart: {
		capability:  func(c AgentCapabilities) bool { return c.SubagentStart },
		supported:   "Delegation policy is enforced at SubagentStart.",
		unsupported: "%s exposes no SubagentStart-equivalent hook.",
	},
	SurfaceConfigChange: {
		capability:  func(c AgentCapabilities) bool { return c.ConfigChange },
		supported:   "Mid-session hook config edits are detected when they happen.",
		unsupported: "%s exposes no ConfigChange-equivalent hook.",
	},
	SurfaceInstructionsLoaded: {
		capability:  func(c AgentCapabilities) bool { return c.InstructionsLoaded },
		supported:   "Context files are scanned when the agent loads them.",
		unsupported: "%s exposes no InstructionsLoaded-equivalent hook.",
	},
	SurfaceElicitation: {
		capability:  func(c AgentCapabilities) bool { return c.Elicitation },
		supported:   "Developer-facing permission prompts are scanned before display.",
		unsupported: "%s exposes no Elicitation-equivalent hook.",
	},
}

// supportSurfaceNotes resolves the note for (spec, surface) by consulting —
// in order — (1) the per-agent override table in supportRenderProfiles, (2)
// the capability-branch template for surfaces whose text is a pure function
// of a Capability bool, (3) the remaining surface-specific logic below.
func supportSurfaceNotes(spec *AgentSpec, key SupportSurfaceKey) string {
	if notes, ok := supportRenderProfiles[spec.ID].surfaceNotes[key]; ok {
		return notes
	}
	if branch, ok := capabilityBranchNotes[key]; ok {
		if branch.capability(spec.Capabilities) {
			return branch.supported
		}
		return fmt.Sprintf(branch.unsupported, spec.Name)
	}
	switch key {
	case SurfaceInteractiveApproval:
		if spec.Capabilities.InteractiveApproval {
			return "Native ask/allow/deny responses are preserved."
		}
		return fmt.Sprintf("%s folds sir's internal ask verdict into %s with remediation text.",
			spec.Name, supportBlockVerb(spec))
	case SurfaceShellClassification:
		if spec.Capabilities.ToolCoverage == ToolCoverageBashOnly {
			return "Every hooked Codex tool call is Bash, so sir's shell classifier is the primary enforcement path."
		}
		return "Bash commands are classified for egress, DNS, persistence, sudo, and install risk."
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

// supportTierLabels maps a SupportTier to its human-facing label used in
// prose. Unknown tiers fall through to the raw string form.
var supportTierLabels = map[SupportTier]string{
	SupportTierReference:  "reference support",
	SupportTierNearParity: "near-parity support",
	SupportTierLimited:    "limited support",
}

func (m SupportManifest) TierLabel() string {
	if label, ok := supportTierLabels[m.SupportTier]; ok {
		return label
	}
	return string(m.SupportTier)
}

// StatusSuffix is the capability-driven caveat shown in status/doctor output.
func (m SupportManifest) StatusSuffix() string {
	parts := []string{m.TierLabel()}
	if m.ToolCoverage == ToolCoverageBashOnly {
		parts = append(parts, "Bash-only")
	}
	return "  (" + strings.Join(parts, ", ") + ")"
}

// supportTierStatusWarningTemplates maps a tier to the format string used by
// StatusWarningLine. The %s placeholder is substituted with the agent name.
// Tiers absent from the map produce an empty line.
var supportTierStatusWarningTemplates = map[SupportTier]string{
	SupportTierNearParity: "             Note: %s is near-parity support; lifecycle coverage remains narrower than Claude Code.\n",
	SupportTierLimited:    "             Warning: %s remains limited support; enforcement is bounded by the upstream Bash-only hook surface.\n",
}

// StatusWarningLine renders the support caveat used by `sir status`.
func (m SupportManifest) StatusWarningLine(agentName string) string {
	tmpl, ok := supportTierStatusWarningTemplates[m.SupportTier]
	if !ok {
		return ""
	}
	return fmt.Sprintf(tmpl, agentName)
}

// supportTierDoctorWarningTemplates maps a tier to the format string used by
// DoctorWarningLine. The %s placeholder is substituted with the agent name.
var supportTierDoctorWarningTemplates = map[SupportTier]string{
	SupportTierNearParity: "  NOTE: %s is near-parity support — file IFC, shell classification, MCP scanning, and credential output scanning are covered, but some lifecycle hooks remain unavailable.\n",
	SupportTierLimited:    "  WARNING: %s is limited support — Bash-mediated actions are guarded, but native writes and MCP tools still depend on sentinel hashing plus end-of-session sweeps.\n",
}

// DoctorWarningLine renders the support caveat used by `sir doctor`.
func (m SupportManifest) DoctorWarningLine(agentName string) string {
	tmpl, ok := supportTierDoctorWarningTemplates[m.SupportTier]
	if !ok {
		return ""
	}
	return fmt.Sprintf(tmpl, agentName)
}

// StatusHeading is the generated heading used by per-agent support docs.
// It consults the supportRenderProfiles table first; unknown agents fall
// through to a generic "## Status: <tier> on <name>" line.
func (m SupportManifest) StatusHeading() string {
	profile, ok := supportRenderProfiles[m.ID]
	if !ok || profile.statusHeadingTemplate == "" {
		return fmt.Sprintf("## Status: %s on %s", m.TierLabel(), m.Name)
	}
	if strings.Contains(profile.statusHeadingTemplate, "%s") {
		return fmt.Sprintf(profile.statusHeadingTemplate, m.MinimumVersion)
	}
	return profile.statusHeadingTemplate
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
