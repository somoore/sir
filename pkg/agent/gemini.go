// Package agent — Gemini CLI adapter.
//
// Gemini uses a legacy { decision:"deny", reason } response shape, wraps
// its tool output in a structured { llmContent, returnDisplay } object,
// and speaks its own "BeforeTool" / "AfterTool" event names which the
// adapter rewrites to sir's internal names. It also emits hook timeouts
// in milliseconds (10000, 5000), not seconds.
//
// All of this is declared in geminiSpec below. The spec's
// ExtractToolOutputFunc handles the llmContent / returnDisplay flattening.
package agent

import "encoding/json"

// extractGeminiToolOutput flattens Gemini's structured tool_response into a
// single string for downstream scanners. Order: llmContent (string) →
// returnDisplay (string) → JSON-encode the whole object as fallback.
// Returns "" when the field is absent.
func extractGeminiToolOutput(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var obj struct {
		LLMContent    json.RawMessage `json:"llmContent"`
		ReturnDisplay json.RawMessage `json:"returnDisplay"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		if s, ok := rawAsString(obj.LLMContent); ok {
			return s
		}
		if s, ok := rawAsString(obj.ReturnDisplay); ok {
			return s
		}
	}
	return string(raw)
}

// rawAsString returns (s, true) if raw decodes as a JSON string. Empty,
// null, or non-string values return ("", false).
func rawAsString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	return "", false
}

// geminiSpec is the pure data declaration for the Gemini CLI adapter.
var geminiSpec = AgentSpec{
	ID:         Gemini,
	Name:       "Gemini CLI",
	MinVersion: "0.36.0",
	Capabilities: AgentCapabilities{
		SupportTier:          SupportTierNearParity,
		ToolCoverage:         ToolCoverageFull,
		InteractiveApproval:  false,
		PostureBackstop:      true,
		FileReadIFC:          true,
		FileWriteIFC:         true,
		ShellClassification:  true,
		MCPToolHooks:         true,
		SessionTerminalSweep: true,
		PreToolUse:           true,
		PostToolUse:          true,
		UserPromptSubmit:     true,
		SessionStart:         true,
		Stop:                 true,
		SessionEnd:           true,
	},

	SupportedSIREvents: []string{
		"PreToolUse",
		"PostToolUse",
		"UserPromptSubmit",
		"SessionStart",
		"SessionEnd",
		"Stop",
	},
	SupportedWireEvents: []string{
		"BeforeTool",
		"AfterTool",
		"BeforeAgent",
		"SessionStart",
		"SessionEnd",
		"AfterAgent",
	},

	ConfigFile:  ".gemini/settings.json",
	ConfigDirs:  []string{".gemini"},
	BinaryNames: []string{"gemini"},
	RuntimeProxyHosts: []string{
		"generativelanguage.googleapis.com",
	},

	ToolNames: map[string]string{
		"read_file":         "Read",
		"read_many_files":   "Read",
		"write_file":        "Write",
		"replace":           "Edit",
		"run_shell_command": "Bash",
		"glob":              "Glob",
		"grep_search":       "Grep",
		"list_directory":    "ListDir",
	},
	EventNames: map[string]string{
		"BeforeTool":  "PreToolUse",
		"AfterTool":   "PostToolUse",
		"BeforeAgent": "UserPromptSubmit",
		"AfterAgent":  "Stop",
	},
	MCPPrefix:    "mcp_",
	MCPSeparator: "_",

	ResponseFormat:         ResponseFormatLegacy,
	HasAskVerdict:          false,
	LegacyDenyLiteral:      "deny",
	EmitLegacyPostEnvelope: false,

	ConfigStrategy: ConfigStrategy{
		ManagedSubtreeKey:   "hooks",
		Layout:              ConfigLayoutMatcherGroups,
		CanonicalBackupFile: "hooks-canonical-gemini.json",
	},
	TimeoutUnit: "milliseconds",
	CommandFlag: "--agent gemini",

	HookRegistrations: []HookRegistration{
		{Event: "PreToolUse", Matcher: ".*", Command: "guard evaluate", Timeout: 10000},
		{Event: "PostToolUse", Matcher: ".*", Command: "guard post-evaluate", Timeout: 10000},
		{Event: "SessionStart", Matcher: "startup|resume|clear", Command: "guard compact-reinject", Timeout: 5000},
		{Event: "UserPromptSubmit", Command: "guard user-prompt", Timeout: 5000},
		{Event: "Stop", Command: "guard session-summary", Timeout: 5000},
		{Event: "SessionEnd", Command: "guard session-end", Timeout: 5000},
	},

	ExtractToolOutputFunc: extractGeminiToolOutput,
}

// GeminiAgent is the Google Gemini CLI adapter.
type GeminiAgent struct{}

// compile-time interface assertions
var _ Agent = (*GeminiAgent)(nil)
var _ MapBuilder = (*GeminiAgent)(nil)

// NewGeminiAgent returns a new Gemini CLI adapter.
func NewGeminiAgent() *GeminiAgent { return &GeminiAgent{} }

func (g *GeminiAgent) ID() AgentID         { return geminiSpec.ID }
func (g *GeminiAgent) Name() string        { return geminiSpec.Name }
func (g *GeminiAgent) MinVersion() string  { return geminiSpec.MinVersion }
func (g *GeminiAgent) GetSpec() *AgentSpec { return &geminiSpec }

func (g *GeminiAgent) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&geminiSpec, raw)
}
func (g *GeminiAgent) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(&geminiSpec, raw)
}

func (g *GeminiAgent) FormatPreToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPreToolUseResponse(&geminiSpec, decision, reason)
}
func (g *GeminiAgent) FormatPostToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPostToolUseResponse(&geminiSpec, decision, reason)
}
func (g *GeminiAgent) FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	return baseFormatLifecycleResponse(&geminiSpec, eventName, decision, reason, context)
}

func (g *GeminiAgent) SupportedEvents() []string { return geminiSpec.SupportedWireEvents }
func (g *GeminiAgent) ConfigPath() string        { return baseConfigPath(&geminiSpec) }
func (g *GeminiAgent) DetectInstallation() bool  { return baseDetectInstallation(&geminiSpec) }

func (g *GeminiAgent) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return baseGenerateHooksConfig(&geminiSpec, sirBinaryPath, mode)
}
func (g *GeminiAgent) GenerateHooksConfigMap(sirBinaryPath, mode string) map[string]interface{} {
	return baseGenerateHooksConfigMap(&geminiSpec, sirBinaryPath, mode)
}
