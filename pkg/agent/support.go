package agent

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
	UnsupportedSIREvents     []string         `json:"unsupported_sir_events"`
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

// PublicSupportManifests returns the public support manifests in the canonical
// CLI order.
func PublicSupportManifests() []SupportManifest {
	return orderedPublicSupportManifests()
}

func orderedPublicSupportManifests() []SupportManifest {
	regs := Registry()
	byID := make(map[AgentID]*AgentSpec, len(regs))
	for _, reg := range regs {
		byID[reg.ID] = reg.Spec
	}
	canonical := []AgentID{Claude, Gemini, Codex}
	out := make([]SupportManifest, 0, len(regs))
	seen := make(map[AgentID]struct{}, len(regs))
	for _, id := range canonical {
		if spec, ok := byID[id]; ok {
			out = append(out, SupportManifestForSpec(spec))
			seen[id] = struct{}{}
		}
	}
	for _, reg := range regs {
		if _, ok := seen[reg.ID]; ok {
			continue
		}
		out = append(out, SupportManifestForSpec(reg.Spec))
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
