// Package agent — conformance test suite.
//
// TestConformance iterates agent.All() and runs the SAME battery of sub-tests
// against every adapter. This is the acceptance test for future adapters:
// any contributor adding a fourth agent gets this suite for free.
//
// The critical sub-test is FuncPointer_ExtractToolOutput_dispatches: it
// proves the refactor avoided the "Go embedding trap" (method override
// via struct embedding does not provide virtual dispatch). If the spec's
// ExtractToolOutputFunc is silently bypassed, that test fails loudly.
package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type supportFixture struct {
	ID                       AgentID                    `json:"id"`
	SupportTier              SupportTier                `json:"support_tier"`
	ToolCoverage             ToolCoverage               `json:"tool_coverage"`
	HookEventCount           int                        `json:"hook_event_count"`
	SupportedSIREvents       []string                   `json:"supported_sir_events"`
	UnsupportedSIREvents     []string                   `json:"unsupported_sir_events"`
	SupportedWireEvents      []string                   `json:"supported_wire_events"`
	RequiredFeatureFlag      string                     `json:"required_feature_flag,omitempty"`
	FeatureFlagEnableCommand string                     `json:"feature_flag_enable_command,omitempty"`
	Surfaces                 map[SupportSurfaceKey]bool `json:"surfaces"`
}

type capabilityWitness struct {
	name         string
	path         string
	parseKind    string
	expectEvent  string
	expectTool   string
	expectCWD    string
	expectOutput string
}

func supportFixturePath(id AgentID) string {
	switch id {
	case Claude:
		return "../../testdata/claude/support.json"
	case Codex:
		return "../../testdata/codex/support.json"
	case Gemini:
		return "../../testdata/gemini/support.json"
	}
	return ""
}

func loadSupportFixture(t *testing.T, id AgentID) supportFixture {
	t.Helper()
	path := supportFixturePath(id)
	if path == "" {
		t.Fatalf("no support fixture for %s", id)
	}
	raw, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var fixture supportFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return fixture
}

func capabilityWitnesses(id AgentID) []capabilityWitness {
	switch id {
	case Claude:
		return []capabilityWitness{
			{name: "pretooluse-read", path: "../../testdata/claude/pretooluse-read-env.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "Read", expectCWD: "/Users/dev/myproject"},
			{name: "posttooluse-read-output", path: "../../testdata/claude/posttooluse-read-output.json", parseKind: "post", expectEvent: "PostToolUse", expectTool: "Read", expectCWD: "/Users/dev/myproject", expectOutput: "DATABASE_URL=postgres://db.internal/app\n"},
			{name: "subagentstart", path: "../../testdata/claude/subagentstart-read-bash.json", parseKind: "pre", expectEvent: "SubagentStart", expectCWD: "/Users/dev/myproject"},
			{name: "userpromptsubmit", path: "../../testdata/claude/userpromptsubmit.json", parseKind: "pre", expectEvent: "UserPromptSubmit", expectCWD: "/Users/dev/myproject"},
			{name: "configchange", path: "../../testdata/claude/configchange-hooks.json", parseKind: "pre", expectEvent: "ConfigChange", expectCWD: "/Users/dev/myproject"},
			{name: "instructionsloaded", path: "../../testdata/claude/instructionsloaded-claude-md.json", parseKind: "pre", expectEvent: "InstructionsLoaded", expectCWD: "/Users/dev/myproject"},
			{name: "elicitation", path: "../../testdata/claude/elicitation-api-key.json", parseKind: "pre", expectEvent: "Elicitation", expectCWD: "/Users/dev/myproject"},
			{name: "stop", path: "../../testdata/claude/stop-response.json", parseKind: "pre", expectEvent: "Stop", expectCWD: "/Users/dev/myproject"},
			{name: "sessionend", path: "../../testdata/claude/sessionend-exit.json", parseKind: "pre", expectEvent: "SessionEnd", expectCWD: "/Users/dev/myproject"},
		}
	case Codex:
		return []capabilityWitness{
			{name: "pretooluse-bash-curl", path: "../../testdata/codex/pretooluse-bash-curl.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "Bash", expectCWD: "/Users/dev/myproject"},
			{name: "posttooluse-bash-output", path: "../../testdata/codex/posttooluse-bash-string-output.json", parseKind: "post", expectEvent: "PostToolUse", expectTool: "Bash", expectCWD: "/Users/dev/myproject", expectOutput: "hello\n"},
			{name: "sessionstart", path: "../../testdata/codex/sessionstart-startup.json", parseKind: "pre", expectEvent: "SessionStart", expectCWD: "/Users/dev/myproject"},
			{name: "userprompt", path: "../../testdata/codex/userpromptsubmit.json", parseKind: "pre", expectEvent: "UserPromptSubmit", expectCWD: "/Users/dev/myproject"},
			{name: "stop", path: "../../testdata/codex/stop-response.json", parseKind: "pre", expectEvent: "Stop", expectCWD: "/Users/dev/myproject"},
		}
	case Gemini:
		return []capabilityWitness{
			{name: "beforetool-shell-curl", path: "../../testdata/gemini/beforetool-shell-curl.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "Bash", expectCWD: "/Users/dev/myproject"},
			{name: "beforetool-read", path: "../../testdata/gemini/beforetool-read-env.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "Read", expectCWD: "/Users/dev/myproject"},
			{name: "beforetool-write", path: "../../testdata/gemini/beforetool-write-geminimd.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "Write", expectCWD: "/Users/dev/myproject"},
			{name: "beforetool-mcp", path: "../../testdata/gemini/beforetool-mcp-slack.json", parseKind: "pre", expectEvent: "PreToolUse", expectTool: "mcp__slack__post_message", expectCWD: "/Users/dev/myproject"},
			{name: "aftertool-shell-output", path: "../../testdata/gemini/aftertool-shell-output.json", parseKind: "post", expectEvent: "PostToolUse", expectTool: "Bash", expectCWD: "/Users/dev/myproject", expectOutput: "hello\n"},
			{name: "beforeagent", path: "../../testdata/gemini/beforeagent-prompt.json", parseKind: "pre", expectEvent: "UserPromptSubmit", expectCWD: "/Users/dev/myproject"},
			{name: "afteragent", path: "../../testdata/gemini/afteragent-response.json", parseKind: "pre", expectEvent: "Stop", expectCWD: "/Users/dev/myproject"},
			{name: "sessionstart", path: "../../testdata/gemini/sessionstart-startup.json", parseKind: "pre", expectEvent: "SessionStart", expectCWD: "/Users/dev/myproject"},
			{name: "sessionend", path: "../../testdata/gemini/sessionend-exit.json", parseKind: "pre", expectEvent: "SessionEnd", expectCWD: "/Users/dev/myproject"},
		}
	}
	return nil
}

func eventSet(events []string) map[string]bool {
	out := make(map[string]bool, len(events))
	for _, ev := range events {
		out[ev] = true
	}
	return out
}

func reverseWireEventName(spec *AgentSpec, sirEvent string) string {
	for native, internal := range spec.EventNames {
		if internal == sirEvent {
			return native
		}
	}
	return sirEvent
}

func generatedWireEvents(t *testing.T, ag Agent) map[string]bool {
	t.Helper()
	builder, ok := ag.(MapBuilder)
	if !ok {
		t.Fatalf("%s does not implement MapBuilder", ag.ID())
	}
	doc := builder.GenerateHooksConfigMap("/usr/local/bin/sir", "standard")
	spec := ag.GetSpec()
	if key := spec.ConfigStrategy.ManagedSubtreeKey; key != "" {
		raw, ok := doc[key]
		if !ok {
			t.Fatalf("generated config missing managed subtree %q", key)
		}
		subtree, ok := raw.(map[string]interface{})
		if !ok {
			t.Fatalf("managed subtree %q has type %T, want map[string]interface{}", key, raw)
		}
		doc = subtree
	}
	out := make(map[string]bool, len(doc))
	for event := range doc {
		out[event] = true
	}
	return out
}

func hasHookRegistration(spec *AgentSpec, event string) bool {
	for _, reg := range spec.HookRegistrations {
		if reg.Event == event {
			return true
		}
	}
	return false
}

func TestConformance(t *testing.T) {
	for _, ag := range All() {
		ag := ag
		t.Run(string(ag.ID()), func(t *testing.T) {
			spec := ag.GetSpec()
			if spec == nil {
				t.Fatal("GetSpec() returned nil")
			}

			t.Run("ID_not_empty", func(t *testing.T) {
				if ag.ID() == "" {
					t.Error("ID() is empty")
				}
			})

			t.Run("Name_not_empty", func(t *testing.T) {
				if ag.Name() == "" {
					t.Error("Name() is empty")
				}
			})

			t.Run("SupportedEvents_not_empty", func(t *testing.T) {
				if len(ag.SupportedEvents()) == 0 {
					t.Error("SupportedEvents() is empty")
				}
			})

			t.Run("Capabilities_declared", func(t *testing.T) {
				switch spec.Capabilities.SupportTier {
				case SupportTierReference, SupportTierNearParity, SupportTierLimited:
				default:
					t.Errorf("invalid support tier %q", spec.Capabilities.SupportTier)
				}
				switch spec.Capabilities.ToolCoverage {
				case ToolCoverageFull, ToolCoverageBashOnly:
				default:
					t.Errorf("invalid tool coverage %q", spec.Capabilities.ToolCoverage)
				}
				if spec.Capabilities.InteractiveApproval != spec.HasAskVerdict {
					t.Errorf("InteractiveApproval (%v) does not match HasAskVerdict (%v)",
						spec.Capabilities.InteractiveApproval, spec.HasAskVerdict)
				}
				if !spec.Capabilities.PostureBackstop {
					t.Error("PostureBackstop must be declared for supported adapters")
				}
			})

			t.Run("SupportContract_valid", func(t *testing.T) {
				if err := ValidateSupportContract(spec); err != nil {
					t.Fatalf("ValidateSupportContract(%s): %v", spec.ID, err)
				}
			})

			t.Run("SupportManifest_matches_fixture", func(t *testing.T) {
				fixture := loadSupportFixture(t, ag.ID())
				manifest := SupportManifestForAgent(ag)
				if manifest.ID != fixture.ID {
					t.Errorf("manifest ID = %q, want %q", manifest.ID, fixture.ID)
				}
				if manifest.SupportTier != fixture.SupportTier {
					t.Errorf("manifest SupportTier = %q, want %q", manifest.SupportTier, fixture.SupportTier)
				}
				if manifest.ToolCoverage != fixture.ToolCoverage {
					t.Errorf("manifest ToolCoverage = %q, want %q", manifest.ToolCoverage, fixture.ToolCoverage)
				}
				if manifest.HookEventCount != fixture.HookEventCount {
					t.Errorf("manifest HookEventCount = %d, want %d", manifest.HookEventCount, fixture.HookEventCount)
				}
				if !reflect.DeepEqual(manifest.SupportedSIREvents, fixture.SupportedSIREvents) {
					t.Errorf("manifest SupportedSIREvents = %v, want %v", manifest.SupportedSIREvents, fixture.SupportedSIREvents)
				}
				if !reflect.DeepEqual(manifest.UnsupportedSIREvents, fixture.UnsupportedSIREvents) {
					t.Errorf("manifest UnsupportedSIREvents = %v, want %v", manifest.UnsupportedSIREvents, fixture.UnsupportedSIREvents)
				}
				if !reflect.DeepEqual(manifest.SupportedWireEvents, fixture.SupportedWireEvents) {
					t.Errorf("manifest SupportedWireEvents = %v, want %v", manifest.SupportedWireEvents, fixture.SupportedWireEvents)
				}
				if manifest.RequiredFeatureFlag != fixture.RequiredFeatureFlag {
					t.Errorf("manifest RequiredFeatureFlag = %q, want %q", manifest.RequiredFeatureFlag, fixture.RequiredFeatureFlag)
				}
				if manifest.FeatureFlagEnableCommand != fixture.FeatureFlagEnableCommand {
					t.Errorf("manifest FeatureFlagEnableCommand = %q, want %q", manifest.FeatureFlagEnableCommand, fixture.FeatureFlagEnableCommand)
				}
				gotSurfaces := map[SupportSurfaceKey]bool{}
				for _, surface := range manifest.Surfaces {
					gotSurfaces[surface.Key] = surface.Supported
				}
				if !reflect.DeepEqual(gotSurfaces, fixture.Surfaces) {
					t.Errorf("manifest surfaces = %v, want %v", gotSurfaces, fixture.Surfaces)
				}
			})

			t.Run("SupportedEvents_are_valid", func(t *testing.T) {
				knownEvents := eventSet(AllSIREvents())
				// Validate sir-internal event names from the spec. Wire
				// names (SupportedEvents() -> SupportedWireEvents) are
				// free-form by design so each agent can keep its native
				// vocabulary; only the internal names they map to need
				// to be in sir's known set.
				if len(spec.SupportedSIREvents) == 0 {
					t.Error("spec.SupportedSIREvents is empty")
				}
				for _, ev := range spec.SupportedSIREvents {
					if !knownEvents[ev] {
						t.Errorf("spec.SupportedSIREvents contains unknown sir event %q", ev)
					}
				}
				// Sanity: wire events and internal events should have
				// the same cardinality (one-to-one mapping).
				if len(spec.SupportedWireEvents) != len(spec.SupportedSIREvents) {
					t.Errorf("SupportedWireEvents (%d) and SupportedSIREvents (%d) length mismatch",
						len(spec.SupportedWireEvents), len(spec.SupportedSIREvents))
				}
				for _, ev := range AllSIREvents() {
					want := false
					for _, supported := range spec.SupportedSIREvents {
						if supported == ev {
							want = true
							break
						}
					}
					if got := spec.Capabilities.SupportsEvent(ev); got != want {
						t.Errorf("Capabilities.SupportsEvent(%q) = %v, want %v", ev, got, want)
					}
				}
			})

			t.Run("EventClaims_have_registrations_and_generated_hooks", func(t *testing.T) {
				wireEvents := generatedWireEvents(t, ag)
				supported := eventSet(spec.SupportedSIREvents)
				for _, ev := range AllSIREvents() {
					wireName := reverseWireEventName(spec, ev)
					_, inGeneratedConfig := wireEvents[wireName]
					hasRegistration := hasHookRegistration(spec, ev)
					if supported[ev] {
						if !hasRegistration {
							t.Errorf("supported event %q has no HookRegistration", ev)
						}
						if !inGeneratedConfig {
							t.Errorf("supported event %q missing from generated config as %q", ev, wireName)
						}
						continue
					}
					if hasRegistration {
						t.Errorf("unsupported event %q unexpectedly has a HookRegistration", ev)
					}
					if inGeneratedConfig {
						t.Errorf("unsupported event %q unexpectedly appears in generated config as %q", ev, wireName)
					}
				}
			})

			t.Run("ConfigStrategy_declared", func(t *testing.T) {
				if spec.ConfigStrategy.CanonicalBackupFile == "" {
					t.Error("ConfigStrategy.CanonicalBackupFile is empty")
				}
				switch spec.ConfigStrategy.EffectiveLayout() {
				case ConfigLayoutMatcherGroups:
				default:
					t.Errorf("unsupported config layout %q", spec.ConfigStrategy.Layout)
				}
			})

			t.Run("ConfigPath_not_empty", func(t *testing.T) {
				if ag.ConfigPath() == "" {
					t.Error("ConfigPath() is empty")
				}
			})

			t.Run("FormatPreToolUse_allow", func(t *testing.T) {
				b, err := ag.FormatPreToolUseResponse("allow", "ok")
				if err != nil {
					t.Fatalf("FormatPreToolUseResponse(allow): %v", err)
				}
				if len(b) == 0 {
					t.Fatal("empty response")
				}
				var v interface{}
				if err := json.Unmarshal(b, &v); err != nil {
					t.Errorf("not valid JSON: %v: %s", err, string(b))
				}
			})

			t.Run("FormatPreToolUse_deny", func(t *testing.T) {
				b, err := ag.FormatPreToolUseResponse("deny", "nope")
				if err != nil {
					t.Fatalf("FormatPreToolUseResponse(deny): %v", err)
				}
				if len(b) == 0 {
					t.Fatal("empty response")
				}
				var v interface{}
				if err := json.Unmarshal(b, &v); err != nil {
					t.Errorf("not valid JSON: %v: %s", err, string(b))
				}
			})

			t.Run("FormatPreToolUse_ask", func(t *testing.T) {
				b, err := ag.FormatPreToolUseResponse("ask", "approve?")
				if err != nil {
					t.Fatalf("FormatPreToolUseResponse(ask): %v", err)
				}
				if len(b) == 0 {
					t.Fatal("empty response")
				}
				var v interface{}
				if err := json.Unmarshal(b, &v); err != nil {
					t.Errorf("not valid JSON: %v: %s", err, string(b))
				}
			})

			t.Run("GenerateHooksConfig_valid_JSON", func(t *testing.T) {
				b, err := ag.GenerateHooksConfig("/usr/local/bin/sir", "standard")
				if err != nil {
					t.Fatalf("GenerateHooksConfig: %v", err)
				}
				var v interface{}
				if err := json.Unmarshal(b, &v); err != nil {
					t.Errorf("not valid JSON: %v: %s", err, string(b))
				}
			})

			t.Run("GenerateHooksConfig_contains_sir_binary", func(t *testing.T) {
				b, err := ag.GenerateHooksConfig("/usr/local/bin/sir", "standard")
				if err != nil {
					t.Fatalf("GenerateHooksConfig: %v", err)
				}
				if !strings.Contains(string(b), "/usr/local/bin/sir") {
					t.Errorf("output missing sir binary path: %s", string(b))
				}
			})

			t.Run("GenerateHooksConfig_contains_agent_flag", func(t *testing.T) {
				if ag.ID() == Claude {
					t.Skip("Claude adapter intentionally omits --agent flag")
				}
				b, err := ag.GenerateHooksConfig("/usr/local/bin/sir", "standard")
				if err != nil {
					t.Fatalf("GenerateHooksConfig: %v", err)
				}
				want := "--agent " + string(ag.ID())
				if !strings.Contains(string(b), want) {
					t.Errorf("output missing %q: %s", want, string(b))
				}
			})

			t.Run("InteractiveApproval_contract", func(t *testing.T) {
				raw, err := ag.FormatPreToolUseResponse("ask", "need approval")
				if err != nil {
					t.Fatalf("FormatPreToolUseResponse(ask): %v", err)
				}
				body := string(raw)
				var envelope map[string]interface{}
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatalf("unmarshal ask response: %v", err)
				}
				reason := body
				if hookSpecific, ok := envelope["hookSpecificOutput"].(map[string]interface{}); ok {
					if permission, ok := hookSpecific["permissionDecision"].(string); ok && spec.Capabilities.InteractiveApproval && permission != "ask" {
						t.Errorf("interactive adapter ask response decision = %q, want %q", permission, "ask")
					}
					if permissionReason, ok := hookSpecific["permissionDecisionReason"].(string); ok {
						reason = permissionReason
					}
				}
				if topReason, ok := envelope["reason"].(string); ok {
					reason = topReason
				}
				if spec.Capabilities.InteractiveApproval {
					if !strings.Contains(body, `"ask"`) {
						t.Errorf("interactive adapter ask response %q does not preserve ask", body)
					}
					if strings.Contains(reason, AskToDenySuffix) {
						t.Errorf("interactive adapter ask response %q unexpectedly contains fallback remediation suffix", body)
					}
					return
				}
				if !strings.Contains(reason, AskToDenySuffix) {
					t.Errorf("non-interactive adapter ask response %q missing remediation suffix", body)
				}
				if strings.Contains(body, `"ask"`) {
					t.Errorf("non-interactive adapter ask response %q unexpectedly preserved ask", body)
				}
			})

			t.Run("Capability_witnesses", func(t *testing.T) {
				witnesses := capabilityWitnesses(ag.ID())
				if len(witnesses) == 0 {
					t.Fatalf("no capability witnesses declared for %s", ag.ID())
				}
				sawNonBash := false
				sawMCP := false
				for _, witness := range witnesses {
					raw, err := os.ReadFile(filepath.Clean(witness.path))
					if err != nil {
						t.Fatalf("read %s: %v", witness.path, err)
					}
					var payload *HookPayload
					switch witness.parseKind {
					case "pre":
						payload, err = ag.ParsePreToolUse(raw)
					case "post":
						payload, err = ag.ParsePostToolUse(raw)
					default:
						t.Fatalf("unknown witness parse kind %q", witness.parseKind)
					}
					if err != nil {
						t.Fatalf("%s: parse failed: %v", witness.name, err)
					}
					if payload.AgentID != ag.ID() {
						t.Errorf("%s: AgentID = %q, want %q", witness.name, payload.AgentID, ag.ID())
					}
					if payload.HookEventName != witness.expectEvent {
						t.Errorf("%s: HookEventName = %q, want %q", witness.name, payload.HookEventName, witness.expectEvent)
					}
					if witness.expectTool != "" && payload.ToolName != witness.expectTool {
						t.Errorf("%s: ToolName = %q, want %q", witness.name, payload.ToolName, witness.expectTool)
					}
					if witness.expectCWD != "" && payload.CWD != witness.expectCWD {
						t.Errorf("%s: CWD = %q, want %q", witness.name, payload.CWD, witness.expectCWD)
					}
					if witness.expectOutput != "" && !strings.Contains(payload.ToolOutput, witness.expectOutput) {
						t.Errorf("%s: ToolOutput = %q, want substring %q", witness.name, payload.ToolOutput, witness.expectOutput)
					}
					if payload.ToolName != "" && payload.ToolName != "Bash" {
						sawNonBash = true
					}
					if strings.HasPrefix(payload.ToolName, "mcp__") {
						sawMCP = true
					}
				}

				switch spec.Capabilities.ToolCoverage {
				case ToolCoverageBashOnly:
					for _, reg := range spec.HookRegistrations {
						if (reg.Event == "PreToolUse" || reg.Event == "PostToolUse") && reg.Matcher != "Bash" {
							t.Errorf("bash-only adapter has %s matcher %q, want %q", reg.Event, reg.Matcher, "Bash")
						}
					}
					if sawNonBash {
						t.Error("bash-only adapter unexpectedly has a non-Bash capability witness")
					}
				case ToolCoverageFull:
					if !sawNonBash {
						t.Error("full-coverage adapter has no non-Bash capability witness")
					}
				}
				if spec.Capabilities.MCPToolHooks && spec.MCPPrefix != "" && !sawMCP {
					t.Error("adapter claims MCP tool hooks but no MCP witness normalized to mcp__*")
				}
			})

			t.Run("FuncPointer_ExtractToolOutput_dispatches", func(t *testing.T) {
				if spec.ExtractToolOutputFunc == nil {
					t.Skipf("%s has no ExtractToolOutputFunc", ag.ID())
				}
				// Synthetic PostToolUse payload with a structured
				// tool_response. If the spec's function pointer is
				// silently bypassed (Go embedding trap), tool_output
				// would come back as raw JSON instead of "EXTRACTED".
				payload := map[string]interface{}{
					"session_id":      "conformance-test",
					"hook_event_name": "PostToolUse",
					"tool_name":       "run_shell_command",
					"tool_input":      map[string]interface{}{},
					"tool_use_id":     "call_conformance",
					"cwd":             "/tmp",
					"tool_response": map[string]interface{}{
						"llmContent":    "EXTRACTED",
						"returnDisplay": "ignored",
						"error":         nil,
					},
				}
				raw, err := json.Marshal(payload)
				if err != nil {
					t.Fatalf("marshal synthetic payload: %v", err)
				}
				got, err := ag.ParsePostToolUse(raw)
				if err != nil {
					t.Fatalf("ParsePostToolUse: %v", err)
				}
				if got.ToolOutput != "EXTRACTED" {
					t.Errorf("ToolOutput = %q, want %q — func pointer dispatch did not fire (Go embedding trap?); got raw JSON fallback", got.ToolOutput, "EXTRACTED")
				}
			})
		})
	}
}
