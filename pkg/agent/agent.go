// Package agent defines the pluggable boundary between sir and the host AI
// coding agent. Each supported agent provides an adapter that translates
// between the agent's wire format and sir's normalized internal types, and
// formats sir's verdicts back into the shape the agent expects.
//
// Adapters currently registered: Claude Code, Codex, Gemini CLI. New agents
// plug in by implementing the Agent interface and registering themselves in
// the package registry below.
//
// Design notes:
//   - HookPayload has NO json tags. Each adapter is responsible for decoding
//     the agent's wire format (via a local wire struct) into this normalized
//     shape. This keeps the hooks package free of agent-specific JSON
//     concerns.
//   - Lifecycle events (UserPromptSubmit, Stop, SessionStart, etc.) are kept
//     simple: their payloads are small and agent-agnostic enough that the
//     existing handlers do their own unmarshal. The agent interface controls
//     OUTPUT formatting for lifecycle events via FormatLifecycleResponse,
//     since that is where adapters actually differ.
//   - FormatPostToolUseResponse returning nil is a valid contract: it means
//     "this agent has no stdout wire contract for PostToolUse; fall through
//     to stderr". Claude Code uses nil; Codex returns a real JSON body.
package agent

// AgentID identifies a specific host agent adapter.
type AgentID string

const (
	// Claude is the Claude Code adapter.
	Claude AgentID = "claude"
	// Codex is the OpenAI Codex adapter.
	Codex AgentID = "codex"
	// Gemini is the Google Gemini CLI adapter.
	Gemini AgentID = "gemini"
)

// AskToDenySuffix is appended to the reason when an "ask" verdict is folded
// into a "deny" / "block" response by an adapter that has no interactive
// approval shape (e.g., Codex, Gemini CLI). Shared across adapters so the
// human-facing copy stays consistent.
const AskToDenySuffix = "\n\nTo approve: re-run after adjusting sir policy (sir allow-host / sir unlock / etc.)"

// AskToDenySuffixPost is the PostToolUse variant — simpler, no specific
// subcommand suggestion since post-hooks generally cannot be "approved" by
// re-running the same tool call.
const AskToDenySuffixPost = "\n\nTo approve: re-run after adjusting sir policy."

// HookPayload is sir's normalized internal representation of a hook event
// payload from the host agent. Adapters decode their wire format into this
// shape so that the hooks package can remain agent-agnostic.
//
// No json tags — adapters handle (un)marshaling via their own wire structs.
type HookPayload struct {
	SessionID     string
	HookEventName string
	ToolName      string
	ToolInput     map[string]interface{}
	ToolUseID     string
	ToolOutput    string // PostToolUse only
	CWD           string
	AgentID       AgentID
}

// Verdict is sir's internal decision for a tool call. Adapters translate this
// into the agent-specific response shape in FormatPreToolUseResponse /
// FormatPostToolUseResponse.
type Verdict struct {
	Decision string // allow, deny, ask, defer
	Reason   string
}

// Agent is the pluggable boundary between sir and a host AI coding agent.
// Adapters implement this interface and register themselves via ForID / All.
type Agent interface {
	// ID returns the stable identifier for this adapter.
	ID() AgentID

	// Name returns the human-readable product name ("Claude Code", "Codex").
	Name() string

	// ParsePreToolUse decodes a PreToolUse hook payload from the agent's wire
	// format into sir's normalized HookPayload.
	ParsePreToolUse(raw []byte) (*HookPayload, error)

	// ParsePostToolUse decodes a PostToolUse hook payload.
	ParsePostToolUse(raw []byte) (*HookPayload, error)

	// FormatPreToolUseResponse produces the wire-format response bytes the
	// agent expects for a PreToolUse verdict.
	FormatPreToolUseResponse(decision, reason string) ([]byte, error)

	// FormatPostToolUseResponse produces the wire-format response bytes for
	// a PostToolUse verdict (most agents expect PostToolUse to write to
	// stderr rather than stdout, but adapters own that policy).
	FormatPostToolUseResponse(decision, reason string) ([]byte, error)

	// FormatLifecycleResponse produces the wire-format response bytes for a
	// non-tool lifecycle event (SessionStart, UserPromptSubmit, Stop, etc.).
	// Adapters use eventName to dispatch to the appropriate format. The
	// context argument carries event-specific content (e.g., the injected
	// message for SessionStart compaction).
	FormatLifecycleResponse(eventName, decision, reason, context string) ([]byte, error)

	// SupportedEvents returns the list of hook event names this adapter
	// registers with the host agent.
	SupportedEvents() []string

	// ConfigPath returns the absolute path to the agent's settings file that
	// sir's install path writes hooks into.
	ConfigPath() string

	// GenerateHooksConfig returns the raw bytes of the hooks config JSON
	// block for this agent. Used by install paths that write the config
	// directly.
	GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error)

	// DetectInstallation returns true if the agent appears to be installed on
	// this machine (used by sir doctor / install flows).
	DetectInstallation() bool

	// MinVersion returns the minimum agent version sir has been validated
	// against. Empty string means "no floor declared".
	MinVersion() string

	// GetSpec returns the adapter's AgentSpec for callers that need to
	// read spec fields (Capabilities, ConfigStrategy, PostInstallFunc, etc.) without
	// reaching into adapter internals.
	GetSpec() *AgentSpec
}

// MapBuilder is an optional extension interface implemented by adapters that
// need to return their hooks config as a map[string]interface{} for merging
// with an existing settings.json. This keeps install.go's merge loop working
// without an extra unmarshal round-trip.
type MapBuilder interface {
	GenerateHooksConfigMap(sirBinaryPath, mode string) map[string]interface{}
}

// Registration is the single source of truth for one supported agent.
type Registration struct {
	ID   AgentID
	Spec *AgentSpec
	New  func() Agent
}

var registry = []Registration{
	{ID: Claude, Spec: &claudeSpec, New: func() Agent { return NewClaudeAgent() }},
	{ID: Codex, Spec: &codexSpec, New: func() Agent { return NewCodexAgent() }},
	{ID: Gemini, Spec: &geminiSpec, New: func() Agent { return NewGeminiAgent() }},
}

// Registry returns the supported agents in deterministic order.
func Registry() []Registration {
	out := make([]Registration, len(registry))
	copy(out, registry)
	return out
}

// ForID returns the adapter registered for the given AgentID, or nil if
// unknown. Callers should fall back to Claude for backward compatibility
// when the flag is absent.
func ForID(id AgentID) Agent {
	if id == "" {
		id = Claude
	}
	for _, reg := range registry {
		if reg.ID == id {
			return reg.New()
		}
	}
	return nil
}

// All returns every known adapter in deterministic order.
func All() []Agent {
	out := make([]Agent, 0, len(registry))
	for _, reg := range registry {
		out = append(out, reg.New())
	}
	return out
}
