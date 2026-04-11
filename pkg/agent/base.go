// Package agent — shared implementation functions driven by AgentSpec.
//
// base.go is the heart of the agent adapter framework: all three adapters
// (Claude Code, Codex, Gemini CLI) delegate into these functions. An
// adapter file is now little more than a package-level var claudeSpec =
// AgentSpec{...} plus a thin struct whose methods forward into here.
//
// CRITICAL DESIGN NOTE: there is no "BaseAgent" struct with methods you can
// override. Go struct embedding does not provide virtual dispatch, so
// pretending to override would silently break behavior. Customization lives
// on AgentSpec as function pointer fields (ExtractToolOutputFunc,
// FormatLifecycleFunc, PostInstallFunc). The adapter shims call these
// shared functions directly with their spec.
package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// baseWirePayload covers the union of fields all three agents' hook
// payloads contain. Individual fields that only one agent emits
// (model, turn_id, transcript_path, timestamp) are accepted for
// forward-compat but not propagated into HookPayload.
type baseWirePayload struct {
	SessionID     string                 `json:"session_id"`
	HookEventName string                 `json:"hook_event_name"`
	ToolName      string                 `json:"tool_name"`
	ToolInput     map[string]interface{} `json:"tool_input"`
	ToolUseID     string                 `json:"tool_use_id"`

	// Claude Code emits tool_output as a plain string.
	ToolOutput string `json:"tool_output,omitempty"`
	// Codex / Gemini emit tool_response as either a string or a
	// structured object.
	ToolResponse json.RawMessage `json:"tool_response,omitempty"`

	CWD string `json:"cwd"`
}

// baseParseHookPayload decodes the wire payload into a normalized
// HookPayload, applying the spec's tool/event name translation and
// extracting tool output via the spec's ExtractToolOutputFunc (with a
// sensible default fallback for agents that just need the string form).
func baseParseHookPayload(spec *AgentSpec, raw []byte) (*HookPayload, error) {
	var wire baseWirePayload
	if err := json.Unmarshal(raw, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal %s hook payload: %w", spec.ID, err)
	}

	var toolOutput string
	switch {
	case wire.ToolOutput != "":
		// Claude path: tool_output is already a string.
		toolOutput = wire.ToolOutput
	case spec.ExtractToolOutputFunc != nil:
		toolOutput = spec.ExtractToolOutputFunc(wire.ToolResponse)
	case len(wire.ToolResponse) > 0:
		toolOutput = defaultExtractToolOutput(wire.ToolResponse)
	}

	return &HookPayload{
		SessionID:     wire.SessionID,
		HookEventName: baseNormalizeEventName(spec, wire.HookEventName),
		ToolName:      baseNormalizeToolName(spec, wire.ToolName),
		ToolInput:     wire.ToolInput,
		ToolUseID:     wire.ToolUseID,
		ToolOutput:    toolOutput,
		CWD:           wire.CWD,
		AgentID:       spec.ID,
	}, nil
}

// defaultExtractToolOutput decodes a raw JSON field that may be either a
// string or a structured object. Strings are unquoted; objects are
// stringified as-is. Codex uses this path (string OR structured).
func defaultExtractToolOutput(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return string(raw)
}

// baseNormalizeEventName applies Spec.EventNames (agent-native -> sir-internal).
// Missing entries pass through unchanged.
func baseNormalizeEventName(spec *AgentSpec, name string) string {
	if v, ok := spec.EventNames[name]; ok {
		return v
	}
	return name
}

// baseNormalizeToolName applies Spec.ToolNames (agent-native -> sir-internal).
// MCP prefix handling: when Spec.MCPPrefix is set and the name starts with
// it, the first occurrence of Spec.MCPSeparator after the prefix separates
// server from tool, and the name is rewritten to sir's "mcp__server__tool"
// form.
func baseNormalizeToolName(spec *AgentSpec, name string) string {
	if spec.MCPPrefix != "" && strings.HasPrefix(name, spec.MCPPrefix) {
		return rewriteMCPName(name, spec.MCPPrefix, spec.MCPSeparator)
	}
	if v, ok := spec.ToolNames[name]; ok {
		return v
	}
	return name
}

// rewriteMCPName converts "<prefix><server><sep><tool>" into
// "mcp__<server>__<tool>". The "<prefix><server>" form (no tool) is also
// accepted and rewritten to "mcp__<server>".
func rewriteMCPName(name, prefix, sep string) string {
	rest := strings.TrimPrefix(name, prefix)
	if rest == "" {
		return name
	}
	idx := strings.Index(rest, sep)
	if idx == -1 {
		return "mcp__" + rest
	}
	server := rest[:idx]
	tool := rest[idx+len(sep):]
	return "mcp__" + server + "__" + tool
}

// baseFormatPreToolUseResponse dispatches on Spec.ResponseFormat.
func baseFormatPreToolUseResponse(spec *AgentSpec, decision, reason string) ([]byte, error) {
	switch spec.ResponseFormat {
	case ResponseFormatClaude:
		return formatClaudePreToolUse(decision, reason)
	default:
		return formatLegacyPreToolUse(decision, reason, spec.LegacyDenyLiteral, spec.HasAskVerdict)
	}
}

// baseFormatPostToolUseResponse dispatches on Spec.ResponseFormat. Claude
// returns nil (stderr fall-through); legacy agents return the flat body.
func baseFormatPostToolUseResponse(spec *AgentSpec, decision, reason string) ([]byte, error) {
	switch spec.ResponseFormat {
	case ResponseFormatClaude:
		// Claude Code's PostToolUse does not honor permissionDecision
		// (it's after-the-fact), so sir writes non-allow reasons to
		// stderr instead. Returning nil here triggers that fallback.
		return nil, nil
	default:
		return formatLegacyPostToolUse(decision, reason, spec.LegacyDenyLiteral, spec.HasAskVerdict, spec.EmitLegacyPostEnvelope)
	}
}

// baseFormatLifecycleResponse calls the spec's FormatLifecycleFunc when set,
// otherwise dispatches to the legacy formatter.
func baseFormatLifecycleResponse(spec *AgentSpec, eventName, decision, reason, context string) ([]byte, error) {
	if spec.FormatLifecycleFunc != nil {
		return spec.FormatLifecycleFunc(eventName, decision, reason, context)
	}
	supported := false
	for _, e := range spec.SupportedSIREvents {
		if e == eventName {
			supported = true
			break
		}
	}
	return formatLegacyLifecycle(spec, eventName, decision, reason, context, supported)
}

// baseConfigPath returns filepath.Join(home, Spec.ConfigFile).
func baseConfigPath(spec *AgentSpec) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, spec.ConfigFile)
}

// baseDetectInstallation checks Spec.ConfigFile, Spec.ConfigDirs, and
// Spec.BinaryNames. Any positive signal returns true.
func baseDetectInstallation(spec *AgentSpec) bool {
	home, err := os.UserHomeDir()
	if err == nil {
		if spec.ConfigFile != "" {
			if _, err := os.Stat(filepath.Join(home, spec.ConfigFile)); err == nil {
				return true
			}
		}
		for _, d := range spec.ConfigDirs {
			if fi, err := os.Stat(filepath.Join(home, d)); err == nil && fi.IsDir() {
				return true
			}
		}
	}
	for _, b := range spec.BinaryNames {
		if _, err := exec.LookPath(b); err == nil {
			return true
		}
	}
	return false
}

// baseGenerateHooksConfigMap walks Spec.HookRegistrations and builds the
// nested map shape: { ManagedSubtreeKey: { WireEvent: [ { matcher?, hooks: [
// { type, command, timeout } ] } ] } }. Event name in the emitted config is
// the reverse-lookup of Spec.EventNames (i.e. the agent-native wire name);
// when no reverse mapping exists, the sir-internal name is used as-is. When
// ManagedSubtreeKey is empty, the emitted document is the hooks map itself.
func baseGenerateHooksConfigMap(spec *AgentSpec, sirBinaryPath, mode string) (map[string]interface{}, error) {
	_ = mode // accepted for forward compatibility
	layout := spec.ConfigStrategy.EffectiveLayout()
	if layout != ConfigLayoutMatcherGroups {
		return nil, fmt.Errorf("unsupported config layout: %s", layout)
	}

	// Build reverse map: sir-internal -> agent-native.
	wireNameFor := func(sirEvent string) string {
		for native, internal := range spec.EventNames {
			if internal == sirEvent {
				return native
			}
		}
		return sirEvent
	}

	hooks := make(map[string]interface{}, len(spec.HookRegistrations))
	for _, reg := range spec.HookRegistrations {
		command := sirBinaryPath + " " + reg.Command
		if spec.CommandFlag != "" {
			command = command + " " + spec.CommandFlag
		}
		group := map[string]interface{}{
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": command,
					"timeout": reg.Timeout,
				},
			},
		}
		if reg.Matcher != "" {
			group["matcher"] = reg.Matcher
		}
		entry := interface{}(group)
		wireName := wireNameFor(reg.Event)
		hooks[wireName] = []interface{}{entry}
	}

	wrapperKey := spec.ConfigStrategy.ManagedSubtreeKey
	if wrapperKey == "" {
		return hooks, nil
	}
	return map[string]interface{}{wrapperKey: hooks}, nil
}

// baseGenerateHooksConfig is the []byte form of baseGenerateHooksConfigMap.
func baseGenerateHooksConfig(spec *AgentSpec, sirBinaryPath, mode string) ([]byte, error) {
	config, err := baseGenerateHooksConfigMap(spec, sirBinaryPath, mode)
	if err != nil {
		return nil, err
	}
	return json.Marshal(config)
}

// specAdapter is the shared Agent + MapBuilder implementation for adapters
// whose methods are pure data-driven forwards into the base* functions. Each
// concrete adapter (ClaudeAgent, CodexAgent, GeminiAgent) embeds specAdapter
// with its own *AgentSpec. Embedding is safe here despite the CRITICAL DESIGN
// NOTE above because the base functions accept the spec as a parameter and do
// not dispatch back into adapter methods — there is no virtual-dispatch hazard
// because nothing overrides. Per-agent customization still lives on the spec
// as function-pointer fields (ExtractToolOutputFunc, FormatLifecycleFunc,
// PostInstallFunc).
type specAdapter struct {
	spec *AgentSpec
}

func (a specAdapter) ID() AgentID         { return a.spec.ID }
func (a specAdapter) Name() string        { return a.spec.Name }
func (a specAdapter) MinVersion() string  { return a.spec.MinVersion }
func (a specAdapter) GetSpec() *AgentSpec { return a.spec }

func (a specAdapter) ParsePreToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(a.spec, raw)
}

func (a specAdapter) ParsePostToolUse(raw []byte) (*HookPayload, error) {
	return baseParseHookPayload(a.spec, raw)
}

func (a specAdapter) FormatPreToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPreToolUseResponse(a.spec, decision, reason)
}

func (a specAdapter) FormatPostToolUseResponse(decision, reason string) ([]byte, error) {
	return baseFormatPostToolUseResponse(a.spec, decision, reason)
}

func (a specAdapter) FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error) {
	return baseFormatLifecycleResponse(a.spec, eventName, decision, reason, context)
}

func (a specAdapter) SupportedEvents() []string { return a.spec.SupportedWireEvents }
func (a specAdapter) ConfigPath() string        { return baseConfigPath(a.spec) }
func (a specAdapter) DetectInstallation() bool  { return baseDetectInstallation(a.spec) }

func (a specAdapter) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return baseGenerateHooksConfig(a.spec, sirBinaryPath, mode)
}

func (a specAdapter) GenerateHooksConfigMap(sirBinaryPath, mode string) (map[string]interface{}, error) {
	return baseGenerateHooksConfigMap(a.spec, sirBinaryPath, mode)
}
