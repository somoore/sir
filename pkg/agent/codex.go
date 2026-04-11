// Package agent — Codex adapter.
//
// Codex uses the legacy { decision:"block", reason } response shape and
// fires hooks for Bash only as of codex-cli 0.118. The adapter is a thin
// wrapper over the shared base functions driven by codexSpec.
//
// PostInstallFunc (ensureCodexFeatureFlag) is wired at init time from
// cmd/sir/install.go to avoid a pkg/agent → cmd/sir circular import.
package agent

// codexSpec is the pure data declaration for the Codex adapter.
var codexSpec = AgentSpec{
	ID:         Codex,
	Name:       "Codex",
	MinVersion: "0.118.0",
	Capabilities: AgentCapabilities{
		SupportTier:          SupportTierLimited,
		ToolCoverage:         ToolCoverageBashOnly,
		InteractiveApproval:  false,
		PostureBackstop:      true,
		FileReadIFC:          true,
		FileWriteIFC:         false,
		ShellClassification:  true,
		MCPToolHooks:         false,
		SessionTerminalSweep: true,
		PreToolUse:           true,
		PostToolUse:          true,
		UserPromptSubmit:     true,
		SessionStart:         true,
		Stop:                 true,
	},

	SupportedSIREvents: []string{
		"PreToolUse",
		"PostToolUse",
		"UserPromptSubmit",
		"SessionStart",
		"Stop",
	},
	SupportedWireEvents: []string{
		"PreToolUse",
		"PostToolUse",
		"UserPromptSubmit",
		"SessionStart",
		"Stop",
	},

	ConfigFile:               ".codex/hooks.json",
	ConfigDirs:               []string{".codex"},
	BinaryNames:              []string{"codex"},
	RuntimeProxyHosts:        []string{"api.openai.com"},
	RequiredFeatureFlag:      "codex_hooks",
	FeatureFlagEnableCommand: "codex features enable codex_hooks",

	ToolNames:  nil,
	EventNames: nil,

	ResponseFormat:         ResponseFormatLegacy,
	HasAskVerdict:          false,
	LegacyDenyLiteral:      "block",
	EmitLegacyPostEnvelope: true,

	ConfigStrategy: ConfigStrategy{
		ManagedSubtreeKey:   "hooks",
		Layout:              ConfigLayoutMatcherGroups,
		CanonicalBackupFile: "hooks-canonical-codex.json",
	},
	TimeoutUnit: "seconds",
	CommandFlag: "--agent codex",

	HookRegistrations: []HookRegistration{
		{Event: "PreToolUse", Matcher: "Bash", Command: "guard evaluate", Timeout: 10},
		{Event: "PostToolUse", Matcher: "Bash", Command: "guard post-evaluate", Timeout: 10},
		{Event: "SessionStart", Matcher: "startup|resume", Command: "guard compact-reinject", Timeout: 5},
		{Event: "UserPromptSubmit", Command: "guard user-prompt", Timeout: 5},
		{Event: "Stop", Command: "guard session-summary", Timeout: 5},
	},

	// PostInstallFunc is wired from cmd/sir/install.go at init time.
	PostInstallFunc: nil,
}

// CodexAgent is the OpenAI Codex CLI adapter.
type CodexAgent struct{}

// compile-time interface assertions
var _ Agent = (*CodexAgent)(nil)
var _ MapBuilder = (*CodexAgent)(nil)

// NewCodexAgent returns a new Codex adapter.
func NewCodexAgent() *CodexAgent { return &CodexAgent{} }

func (c *CodexAgent) ID() AgentID         { return codexSpec.ID }
func (c *CodexAgent) Name() string        { return codexSpec.Name }
func (c *CodexAgent) MinVersion() string  { return codexSpec.MinVersion }
func (c *CodexAgent) GetSpec() *AgentSpec { return &codexSpec }

func (c *CodexAgent) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&codexSpec, raw)
}
func (c *CodexAgent) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&codexSpec, raw)
}

func (c *CodexAgent) FormatPreToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPreToolUseResponse(&codexSpec, decision, reason)
}
func (c *CodexAgent) FormatPostToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPostToolUseResponse(&codexSpec, decision, reason)
}
func (c *CodexAgent) FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	return baseFormatLifecycleResponse(&codexSpec, eventName, decision, reason, context)
}

func (c *CodexAgent) SupportedEvents() []string { return codexSpec.SupportedWireEvents }
func (c *CodexAgent) ConfigPath() string        { return baseConfigPath(&codexSpec) }
func (c *CodexAgent) DetectInstallation() bool  { return baseDetectInstallation(&codexSpec) }

func (c *CodexAgent) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return baseGenerateHooksConfig(&codexSpec, sirBinaryPath, mode)
}
func (c *CodexAgent) GenerateHooksConfigMap(sirBinaryPath, mode string) (map[string]interface{}, error) {
	return baseGenerateHooksConfigMap(&codexSpec, sirBinaryPath, mode)
}
