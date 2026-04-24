package agent

// equivalence_test.go — pre-refactor SAFETY NET (Step 14).
//
// This file captures byte-exact golden outputs for every adapter method on
// every adapter (Claude Code, Codex, Gemini CLI). It exists so that the
// upcoming agent-adapter framework refactor can be proven behavior-preserving:
// any change to the wire format an adapter emits will fail one of these
// assertions.
//
// Stability notes:
//   - encoding/json marshals map[string]interface{} keys in lexicographic
//     order, so all map-based payloads are deterministic.
//   - struct-based payloads marshal in field declaration order.
//   - No timestamps, no IDs, no random values are involved in any of the
//     captured outputs.
//
// If a golden fails AGAINST CURRENT (pre-refactor) CODE, the golden is wrong:
// fix the golden, not the adapter. After the refactor, treat any failure as
// a behavior change to investigate.

import (
	"testing"
)

// ---------------------------------------------------------------------------
// PreToolUse / PostToolUse / Lifecycle output goldens
// ---------------------------------------------------------------------------

func TestOutputEquivalence_Claude_PreToolUse(t *testing.T) {
	a := &ClaudeAgent{}
	cases := []struct {
		decision, reason string
		want             string
	}{
		{"allow", "", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow"}}`},
		{"deny", "test reason", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"test reason"}}`},
		{"ask", "test reason", `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"test reason"}}`},
	}
	for _, c := range cases {
		got, err := a.FormatPreToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Pre %s/%q: err=%v", c.decision, c.reason, err)
		}
		if string(got) != c.want {
			t.Errorf("Pre %s/%q\n got: %s\nwant: %s", c.decision, c.reason, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Claude_PostToolUse(t *testing.T) {
	a := &ClaudeAgent{}
	// Claude PostToolUse always returns nil bytes (stderr fall-through).
	for _, c := range []struct{ decision, reason string }{
		{"allow", ""},
		{"deny", "bad output"},
		{"ask", "test reason"},
	} {
		got, err := a.FormatPostToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Post %s/%q: err=%v", c.decision, c.reason, err)
		}
		if got != nil {
			t.Errorf("Post %s/%q expected nil, got %q", c.decision, c.reason, string(got))
		}
	}
}

func TestOutputEquivalence_Claude_Lifecycle(t *testing.T) {
	a := &ClaudeAgent{}
	type tc struct {
		event, decision, reason, context string
		want                             string // empty means expect nil bytes
		wantNil                          bool
	}
	cases := []tc{
		// SessionStart: returns {"message":<context>} regardless of decision
		{"SessionStart", "allow", "lifecycle reason", "ctx text", `{"message":"ctx text"}`, false},
		{"SessionStart", "deny", "lifecycle reason", "ctx text", `{"message":"ctx text"}`, false},
		{"SessionStart", "block", "lifecycle reason", "ctx text", `{"message":"ctx text"}`, false},
		{"SessionStart", "", "lifecycle reason", "ctx text", `{"message":"ctx text"}`, false},
		{"SessionStart", "allow", "lifecycle reason", "", `{}`, false},
		// SubagentStart: hookSpecificOutput
		{"SubagentStart", "allow", "lifecycle reason", "", `{"hookSpecificOutput":{"hookEventName":"SubagentStart","permissionDecision":"allow","permissionDecisionReason":"lifecycle reason"}}`, false},
		{"SubagentStart", "deny", "lifecycle reason", "", `{"hookSpecificOutput":{"hookEventName":"SubagentStart","permissionDecision":"deny","permissionDecisionReason":"lifecycle reason"}}`, false},
		{"SubagentStart", "block", "lifecycle reason", "", `{"hookSpecificOutput":{"hookEventName":"SubagentStart","permissionDecision":"block","permissionDecisionReason":"lifecycle reason"}}`, false},
		{"SubagentStart", "", "lifecycle reason", "", `{"hookSpecificOutput":{"hookEventName":"SubagentStart","permissionDecision":"","permissionDecisionReason":"lifecycle reason"}}`, false},
		// All other events: nil bytes
		{"Stop", "allow", "lifecycle reason", "ctx text", "", true},
		{"Stop", "deny", "lifecycle reason", "ctx text", "", true},
		{"UserPromptSubmit", "allow", "lifecycle reason", "ctx text", "", true},
		{"UserPromptSubmit", "deny", "lifecycle reason", "ctx text", "", true},
		{"SessionEnd", "allow", "lifecycle reason", "ctx text", "", true},
		{"ConfigChange", "allow", "lifecycle reason", "ctx text", "", true},
		{"InstructionsLoaded", "allow", "lifecycle reason", "ctx text", "", true},
		{"Elicitation", "allow", "lifecycle reason", "ctx text", "", true},
	}
	for _, c := range cases {
		got, err := a.FormatLifecycleResponse(c.event, c.decision, c.reason, c.context)
		if err != nil {
			t.Fatalf("Life %s/%s: err=%v", c.event, c.decision, err)
		}
		if c.wantNil {
			if got != nil {
				t.Errorf("Life %s/%s expected nil, got %q", c.event, c.decision, string(got))
			}
			continue
		}
		if string(got) != c.want {
			t.Errorf("Life %s/%s\n got: %s\nwant: %s", c.event, c.decision, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Claude_HooksConfig(t *testing.T) {
	a := &ClaudeAgent{}
	want := `{"hooks":{"ConfigChange":[{"hooks":[{"command":"/usr/local/bin/sir guard config-change","timeout":5,"type":"command"}]}],"Elicitation":[{"hooks":[{"command":"/usr/local/bin/sir guard elicitation","timeout":5,"type":"command"}]}],"InstructionsLoaded":[{"hooks":[{"command":"/usr/local/bin/sir guard instructions-loaded","timeout":5,"type":"command"}]}],"PermissionRequest":[{"hooks":[{"command":"/usr/local/bin/sir guard permission-request","timeout":10,"type":"command"}],"matcher":".*"}],"PostToolUse":[{"hooks":[{"command":"/usr/local/bin/sir guard post-evaluate","timeout":10,"type":"command"}],"matcher":".*"}],"PreToolUse":[{"hooks":[{"command":"/usr/local/bin/sir guard evaluate","timeout":10,"type":"command"}],"matcher":".*"}],"SessionEnd":[{"hooks":[{"command":"/usr/local/bin/sir guard session-end","timeout":5,"type":"command"}]}],"SessionStart":[{"hooks":[{"command":"/usr/local/bin/sir guard compact-reinject","timeout":5,"type":"command"}]}],"Stop":[{"hooks":[{"command":"/usr/local/bin/sir guard session-summary","timeout":5,"type":"command"}]}],"SubagentStart":[{"hooks":[{"command":"/usr/local/bin/sir guard subagent-start","timeout":10,"type":"command"}],"matcher":".*"}],"UserPromptSubmit":[{"hooks":[{"command":"/usr/local/bin/sir guard user-prompt","timeout":5,"type":"command"}]}]}}`
	got, err := a.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != want {
		t.Errorf("\n got: %s\nwant: %s", string(got), want)
	}
}

// ---------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------

func TestOutputEquivalence_Codex_PreToolUse(t *testing.T) {
	a := &CodexAgent{}
	cases := []struct {
		decision, reason string
		want             string
	}{
		{"allow", "", `{}`},
		{"deny", "test reason", `{"decision":"block","reason":"test reason"}`},
		{"ask", "test reason", `{"decision":"block","reason":"test reason` + "\\n\\n" + `To approve: re-run after adjusting sir policy (sir allow-host / sir unlock / etc.)"}`},
	}
	for _, c := range cases {
		got, err := a.FormatPreToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Pre %s/%q: err=%v", c.decision, c.reason, err)
		}
		if string(got) != c.want {
			t.Errorf("Pre %s/%q\n got: %s\nwant: %s", c.decision, c.reason, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Codex_PostToolUse(t *testing.T) {
	a := &CodexAgent{}
	cases := []struct {
		decision, reason string
		want             string
	}{
		{"allow", "", `{}`},
		{"deny", "bad output", `{"decision":"block","hookSpecificOutput":{"additionalContext":"bad output","hookEventName":"PostToolUse"},"reason":"bad output"}`},
		{"ask", "test reason", `{"decision":"block","hookSpecificOutput":{"additionalContext":"test reason` + "\\n\\n" + `To approve: re-run after adjusting sir policy.","hookEventName":"PostToolUse"},"reason":"test reason` + "\\n\\n" + `To approve: re-run after adjusting sir policy."}`},
	}
	for _, c := range cases {
		got, err := a.FormatPostToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Post %s/%q: err=%v", c.decision, c.reason, err)
		}
		if string(got) != c.want {
			t.Errorf("Post %s/%q\n got: %s\nwant: %s", c.decision, c.reason, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Codex_Lifecycle(t *testing.T) {
	a := &CodexAgent{}
	cases := []struct {
		event, decision, reason, context string
		want                             string
	}{
		// SessionStart with context
		{"SessionStart", "allow", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`},
		{"SessionStart", "deny", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`},
		{"SessionStart", "", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`},
		// SessionStart empty context
		{"SessionStart", "allow", "lifecycle reason", "", `{}`},
		// Stop: only "block" decision returns body
		{"Stop", "allow", "lifecycle reason", "ctx text", `{}`},
		{"Stop", "deny", "lifecycle reason", "ctx text", `{}`},
		{"Stop", "block", "lifecycle reason", "ctx text", `{"decision":"block","reason":"lifecycle reason"}`},
		{"Stop", "", "lifecycle reason", "ctx text", `{}`},
		// Everything else returns {}
		{"UserPromptSubmit", "allow", "lifecycle reason", "ctx text", `{}`},
		{"UserPromptSubmit", "deny", "lifecycle reason", "ctx text", `{}`},
		{"UserPromptSubmit", "block", "lifecycle reason", "ctx text", `{}`},
		{"SessionEnd", "allow", "lifecycle reason", "ctx text", `{}`},
		{"ConfigChange", "allow", "lifecycle reason", "ctx text", `{}`},
		{"InstructionsLoaded", "allow", "lifecycle reason", "ctx text", `{}`},
		{"Elicitation", "allow", "lifecycle reason", "ctx text", `{}`},
		{"SubagentStart", "allow", "lifecycle reason", "ctx text", `{}`},
	}
	for _, c := range cases {
		got, err := a.FormatLifecycleResponse(c.event, c.decision, c.reason, c.context)
		if err != nil {
			t.Fatalf("Life %s/%s: err=%v", c.event, c.decision, err)
		}
		if string(got) != c.want {
			t.Errorf("Life %s/%s\n got: %s\nwant: %s", c.event, c.decision, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Codex_HooksConfig(t *testing.T) {
	a := &CodexAgent{}
	want := `{"hooks":{"PermissionRequest":[{"hooks":[{"command":"/usr/local/bin/sir guard permission-request --agent codex","timeout":10,"type":"command"}],"matcher":".*"}],"PostToolUse":[{"hooks":[{"command":"/usr/local/bin/sir guard post-evaluate --agent codex","timeout":10,"type":"command"}],"matcher":"Bash|apply_patch|Edit|Write|mcp__.*"}],"PreToolUse":[{"hooks":[{"command":"/usr/local/bin/sir guard evaluate --agent codex","timeout":10,"type":"command"}],"matcher":"Bash|apply_patch|Edit|Write|mcp__.*"}],"SessionStart":[{"hooks":[{"command":"/usr/local/bin/sir guard compact-reinject --agent codex","timeout":5,"type":"command"}],"matcher":"startup|resume"}],"Stop":[{"hooks":[{"command":"/usr/local/bin/sir guard session-summary --agent codex","timeout":5,"type":"command"}]}],"UserPromptSubmit":[{"hooks":[{"command":"/usr/local/bin/sir guard user-prompt --agent codex","timeout":5,"type":"command"}]}]}}`
	got, err := a.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != want {
		t.Errorf("\n got: %s\nwant: %s", string(got), want)
	}
}

// ---------------------------------------------------------------------------
// Gemini
// ---------------------------------------------------------------------------

func TestOutputEquivalence_Gemini_PreToolUse(t *testing.T) {
	a := &GeminiAgent{}
	cases := []struct {
		decision, reason string
		want             string
	}{
		{"allow", "", `{}`},
		{"deny", "test reason", `{"decision":"deny","reason":"test reason"}`},
		{"ask", "test reason", `{"decision":"deny","reason":"test reason` + "\\n\\n" + `To approve: re-run after adjusting sir policy (sir allow-host / sir unlock / etc.)"}`},
	}
	for _, c := range cases {
		got, err := a.FormatPreToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Pre %s/%q: err=%v", c.decision, c.reason, err)
		}
		if string(got) != c.want {
			t.Errorf("Pre %s/%q\n got: %s\nwant: %s", c.decision, c.reason, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Gemini_PostToolUse(t *testing.T) {
	a := &GeminiAgent{}
	cases := []struct {
		decision, reason string
		want             string
	}{
		{"allow", "", `{}`},
		{"deny", "bad output", `{"decision":"deny","reason":"bad output"}`},
		{"ask", "test reason", `{"decision":"deny","reason":"test reason` + "\\n\\n" + `To approve: re-run after adjusting sir policy."}`},
	}
	for _, c := range cases {
		got, err := a.FormatPostToolUseResponse(c.decision, c.reason)
		if err != nil {
			t.Fatalf("Post %s/%q: err=%v", c.decision, c.reason, err)
		}
		if string(got) != c.want {
			t.Errorf("Post %s/%q\n got: %s\nwant: %s", c.decision, c.reason, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Gemini_Lifecycle(t *testing.T) {
	a := &GeminiAgent{}
	type tc struct {
		event, decision, reason, context string
		want                             string
		wantNil                          bool
	}
	cases := []tc{
		// SessionStart with context
		{"SessionStart", "allow", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`, false},
		{"SessionStart", "deny", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`, false},
		{"SessionStart", "", "lifecycle reason", "ctx text", `{"hookSpecificOutput":{"additionalContext":"ctx text","hookEventName":"SessionStart"}}`, false},
		// SessionStart empty context
		{"SessionStart", "allow", "lifecycle reason", "", `{}`, false},
		// UserPromptSubmit: deny/block returns body, else {}
		{"UserPromptSubmit", "allow", "lifecycle reason", "ctx text", `{}`, false},
		{"UserPromptSubmit", "deny", "lifecycle reason", "ctx text", `{"decision":"deny","reason":"lifecycle reason"}`, false},
		{"UserPromptSubmit", "block", "lifecycle reason", "ctx text", `{"decision":"deny","reason":"lifecycle reason"}`, false},
		{"UserPromptSubmit", "", "lifecycle reason", "ctx text", `{}`, false},
		// Stop, SessionEnd: always {}
		{"Stop", "allow", "lifecycle reason", "ctx text", `{}`, false},
		{"Stop", "deny", "lifecycle reason", "ctx text", `{}`, false},
		{"Stop", "block", "lifecycle reason", "ctx text", `{}`, false},
		{"SessionEnd", "allow", "lifecycle reason", "ctx text", `{}`, false},
		{"SessionEnd", "deny", "lifecycle reason", "ctx text", `{}`, false},
		// Unsupported events: nil
		{"ConfigChange", "allow", "lifecycle reason", "ctx text", "", true},
		{"InstructionsLoaded", "allow", "lifecycle reason", "ctx text", "", true},
		{"Elicitation", "allow", "lifecycle reason", "ctx text", "", true},
		{"SubagentStart", "allow", "lifecycle reason", "ctx text", "", true},
	}
	for _, c := range cases {
		got, err := a.FormatLifecycleResponse(c.event, c.decision, c.reason, c.context)
		if err != nil {
			t.Fatalf("Life %s/%s: err=%v", c.event, c.decision, err)
		}
		if c.wantNil {
			if got != nil {
				t.Errorf("Life %s/%s expected nil, got %q", c.event, c.decision, string(got))
			}
			continue
		}
		if string(got) != c.want {
			t.Errorf("Life %s/%s\n got: %s\nwant: %s", c.event, c.decision, string(got), c.want)
		}
	}
}

func TestOutputEquivalence_Gemini_HooksConfig(t *testing.T) {
	a := &GeminiAgent{}
	want := `{"hooks":{"AfterAgent":[{"hooks":[{"command":"/usr/local/bin/sir guard session-summary --agent gemini","timeout":5000,"type":"command"}]}],"AfterTool":[{"hooks":[{"command":"/usr/local/bin/sir guard post-evaluate --agent gemini","timeout":10000,"type":"command"}],"matcher":".*"}],"BeforeAgent":[{"hooks":[{"command":"/usr/local/bin/sir guard user-prompt --agent gemini","timeout":5000,"type":"command"}]}],"BeforeTool":[{"hooks":[{"command":"/usr/local/bin/sir guard evaluate --agent gemini","timeout":10000,"type":"command"}],"matcher":".*"}],"SessionEnd":[{"hooks":[{"command":"/usr/local/bin/sir guard session-end --agent gemini","timeout":5000,"type":"command"}]}],"SessionStart":[{"hooks":[{"command":"/usr/local/bin/sir guard compact-reinject --agent gemini","timeout":5000,"type":"command"}],"matcher":"startup|resume|clear"}]}}`
	got, err := a.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != want {
		t.Errorf("\n got: %s\nwant: %s", string(got), want)
	}
}
