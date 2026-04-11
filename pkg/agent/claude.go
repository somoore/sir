// Package agent — Claude Code adapter.
//
// The adapter is now a thin wrapper: a package-level AgentSpec describes
// the data (tool names, event names, response format, hook registrations),
// and ClaudeAgent's methods delegate into the shared base functions with
// &claudeSpec. Lifecycle formatting is Claude-specific enough that we
// route it through Spec.FormatLifecycleFunc rather than the legacy shared
// helper.
package agent

import "encoding/json"

// claudeHookSpecificOutput is the inner hookSpecificOutput response shape
// Claude Code expects for PreToolUse / PostToolUse.
type claudeHookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason,omitempty"`
}

// claudeHookResponse is the outer response envelope Claude Code expects.
type claudeHookResponse struct {
	HookSpecificOutput claudeHookSpecificOutput `json:"hookSpecificOutput"`
}

// claudeCompactResponse is the response shape for SessionStart (compact).
type claudeCompactResponse struct {
	Message string `json:"message,omitempty"`
}

// formatClaudeLifecycleResponse produces the Claude Code response shape for
// a lifecycle event.
//
//	SessionStart       → { "message": <context> }  (compact reinject)
//	SubagentStart      → hookSpecificOutput with SubagentStart eventName
//	everything else    → nil, nil (stderr fall-through)
func formatClaudeLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	switch eventName {
	case "SessionStart":
		return json.Marshal(claudeCompactResponse{Message: context})
	case "SubagentStart":
		return json.Marshal(claudeHookResponse{
			HookSpecificOutput: claudeHookSpecificOutput{
				HookEventName:            "SubagentStart",
				PermissionDecision:       decision,
				PermissionDecisionReason: reason,
			},
		})
	}
	return nil, nil
}

// claudeSpec is the pure data declaration for the Claude Code adapter.
var claudeSpec = AgentSpec{
	ID:         Claude,
	Name:       "Claude Code",
	MinVersion: "",
	Capabilities: AgentCapabilities{
		SupportTier:          SupportTierReference,
		ToolCoverage:         ToolCoverageFull,
		InteractiveApproval:  true,
		PostureBackstop:      true,
		FileReadIFC:          true,
		FileWriteIFC:         true,
		ShellClassification:  true,
		MCPToolHooks:         true,
		SessionTerminalSweep: true,
		PreToolUse:           true,
		PostToolUse:          true,
		UserPromptSubmit:     true,
		SubagentStart:        true,
		SessionStart:         true,
		ConfigChange:         true,
		InstructionsLoaded:   true,
		Stop:                 true,
		SessionEnd:           true,
		Elicitation:          true,
	},

	SupportedSIREvents: []string{
		"PreToolUse",
		"PostToolUse",
		"SubagentStart",
		"UserPromptSubmit",
		"SessionStart",
		"ConfigChange",
		"InstructionsLoaded",
		"Stop",
		"SessionEnd",
		"Elicitation",
	},
	// Claude's wire event names ARE the sir-internal names.
	SupportedWireEvents: []string{
		"PreToolUse",
		"PostToolUse",
		"SubagentStart",
		"UserPromptSubmit",
		"SessionStart",
		"ConfigChange",
		"InstructionsLoaded",
		"Stop",
		"SessionEnd",
		"Elicitation",
	},

	ConfigFile:  ".claude/settings.json",
	ConfigDirs:  []string{".claude"},
	BinaryNames: nil,
	RuntimeProxyHosts: []string{
		"api.anthropic.com",
	},

	ToolNames:  nil, // Claude uses sir-internal names natively.
	EventNames: nil, // Same.

	ResponseFormat: ResponseFormatClaude,
	HasAskVerdict:  true,

	ConfigStrategy: ConfigStrategy{
		ManagedSubtreeKey:   "hooks",
		Layout:              ConfigLayoutMatcherGroups,
		CanonicalBackupFile: "hooks-canonical.json",
	},
	TimeoutUnit: "seconds",
	CommandFlag: "", // Claude is the default; no --agent flag.

	HookRegistrations: []HookRegistration{
		{Event: "PreToolUse", Matcher: ".*", Command: "guard evaluate", Timeout: 10},
		{Event: "PostToolUse", Matcher: ".*", Command: "guard post-evaluate", Timeout: 10},
		{Event: "SubagentStart", Matcher: ".*", Command: "guard subagent-start", Timeout: 10},
		{Event: "UserPromptSubmit", Command: "guard user-prompt", Timeout: 5},
		{Event: "SessionStart", Command: "guard compact-reinject", Timeout: 5},
		{Event: "ConfigChange", Command: "guard config-change", Timeout: 5},
		{Event: "InstructionsLoaded", Command: "guard instructions-loaded", Timeout: 5},
		{Event: "Stop", Command: "guard session-summary", Timeout: 5},
		{Event: "SessionEnd", Command: "guard session-end", Timeout: 5},
		{Event: "Elicitation", Command: "guard elicitation", Timeout: 5},
	},

	FormatLifecycleFunc: formatClaudeLifecycleResponse,
}

// ClaudeAgent is the Claude Code adapter. Its Agent/MapBuilder methods come
// from the embedded specAdapter bound to claudeSpec — nothing per-agent lives
// here except the spec, the lifecycle formatter, and the constructor.
type ClaudeAgent struct{ specAdapter }

// compile-time interface assertions
var _ Agent = (*ClaudeAgent)(nil)
var _ MapBuilder = (*ClaudeAgent)(nil)

// NewClaudeAgent returns a new Claude Code adapter.
func NewClaudeAgent() *ClaudeAgent { return &ClaudeAgent{specAdapter{spec: &claudeSpec}} }
