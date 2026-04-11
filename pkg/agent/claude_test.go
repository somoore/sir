package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeAgent_ID verifies the adapter identity.
func TestClaudeAgent_ID(t *testing.T) {
	c := &ClaudeAgent{}
	if c.ID() != Claude {
		t.Errorf("ID() = %q, want %q", c.ID(), Claude)
	}
	if c.Name() != "Claude Code" {
		t.Errorf("Name() = %q, want %q", c.Name(), "Claude Code")
	}
}

// TestClaudeAgent_SupportedEvents asserts all ten hook events are present.
func TestClaudeAgent_SupportedEvents(t *testing.T) {
	c := &ClaudeAgent{}
	events := c.SupportedEvents()
	want := []string{
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
	}
	if len(events) != len(want) {
		t.Fatalf("SupportedEvents len = %d, want %d", len(events), len(want))
	}
	got := map[string]bool{}
	for _, e := range events {
		got[e] = true
	}
	for _, w := range want {
		if !got[w] {
			t.Errorf("missing event %q", w)
		}
	}
}

// TestClaudeAgent_RoundTrip_PreToolUse parses a real Claude PreToolUse JSON
// fixture, formats an allow response, and asserts the response shape.
func TestClaudeAgent_RoundTrip_PreToolUse(t *testing.T) {
	c := &ClaudeAgent{}
	// Use the pre-shipped allow-curl-localhost.json fixture
	fixturePath := filepath.Join("..", "..", "testdata", "hook-payloads", "allow-curl-localhost.json")
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	payload, err := c.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if payload.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash", payload.ToolName)
	}
	if payload.AgentID != Claude {
		t.Errorf("AgentID = %q, want %q", payload.AgentID, Claude)
	}
	cmd, _ := payload.ToolInput["command"].(string)
	if !strings.Contains(cmd, "curl") {
		t.Errorf("ToolInput[command] = %q, want curl", cmd)
	}

	// Format an allow response
	resp, err := c.FormatPreToolUseResponse("allow", "localhost is safe")
	if err != nil {
		t.Fatalf("FormatPreToolUseResponse: %v", err)
	}
	// Must be valid JSON containing hookSpecificOutput
	var envelope map[string]interface{}
	if err := json.Unmarshal(resp, &envelope); err != nil {
		t.Fatalf("response not valid JSON: %v\n%s", err, resp)
	}
	hso, ok := envelope["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatal("missing hookSpecificOutput in response")
	}
	if hso["permissionDecision"] != "allow" {
		t.Errorf("permissionDecision = %v, want allow", hso["permissionDecision"])
	}
	if hso["hookEventName"] != "PreToolUse" {
		t.Errorf("hookEventName = %v, want PreToolUse", hso["hookEventName"])
	}
}

// TestClaudeAgent_FormatDeny asserts that a deny response contains the
// reason and the correct permissionDecision.
func TestClaudeAgent_FormatDeny(t *testing.T) {
	c := &ClaudeAgent{}
	reason := "sir blocks this because reasons"
	data, err := c.FormatPreToolUseResponse("deny", reason)
	if err != nil {
		t.Fatalf("FormatPreToolUseResponse: %v", err)
	}
	s := string(data)
	if !strings.Contains(s, `"permissionDecision":"deny"`) {
		t.Errorf("response missing permissionDecision deny: %s", s)
	}
	if !strings.Contains(s, reason) {
		t.Errorf("response missing reason %q: %s", reason, s)
	}
	if !strings.Contains(s, `"hookEventName":"PreToolUse"`) {
		t.Errorf("response missing hookEventName PreToolUse: %s", s)
	}
}

// TestClaudeAgent_FormatLifecycleResponse_SessionStart asserts compact
// reinjection produces the { message: ... } shape Claude Code expects.
func TestClaudeAgent_FormatLifecycleResponse_SessionStart(t *testing.T) {
	c := &ClaudeAgent{}
	data, err := c.FormatLifecycleResponse("SessionStart", "allow", "", "[sir] reminder text")
	if err != nil {
		t.Fatalf("FormatLifecycleResponse: %v", err)
	}
	var env map[string]interface{}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	if env["message"] != "[sir] reminder text" {
		t.Errorf("message = %v, want reminder text", env["message"])
	}
}

// TestClaudeAgent_FormatLifecycleResponse_Silent asserts events that should
// produce no stdout output return nil bytes.
func TestClaudeAgent_FormatLifecycleResponse_Silent(t *testing.T) {
	c := &ClaudeAgent{}
	for _, ev := range []string{"UserPromptSubmit", "Stop", "SessionEnd", "ConfigChange", "Elicitation", "InstructionsLoaded"} {
		data, err := c.FormatLifecycleResponse(ev, "allow", "", "")
		if err != nil {
			t.Errorf("%s: err = %v", ev, err)
		}
		if data != nil {
			t.Errorf("%s: expected nil bytes, got %q", ev, data)
		}
	}
}

// TestClaudeAgent_GenerateHooksConfigMap asserts the shape matches what the
// install merge loop expects.
func TestClaudeAgent_GenerateHooksConfigMap(t *testing.T) {
	c := &ClaudeAgent{}
	cfg := mustHooksConfigMap(t, c, "/usr/local/bin/sir", "guard")
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		t.Fatal("missing hooks key")
	}
	arr, ok := hooks["PreToolUse"].([]interface{})
	if !ok {
		t.Fatalf("PreToolUse not []interface{}, got %T", hooks["PreToolUse"])
	}
	if len(arr) == 0 {
		t.Fatal("PreToolUse empty")
	}
	mg, ok := arr[0].(map[string]interface{})
	if !ok {
		t.Fatal("matcher group not map")
	}
	if mg["matcher"] != ".*" {
		t.Errorf("matcher = %v, want .*", mg["matcher"])
	}
	inner, ok := mg["hooks"].([]interface{})
	if !ok {
		t.Fatalf("inner hooks not []interface{}, got %T", mg["hooks"])
	}
	first, ok := inner[0].(map[string]interface{})
	if !ok {
		t.Fatal("inner hook not map")
	}
	cmd, _ := first["command"].(string)
	if cmd != "/usr/local/bin/sir guard evaluate" {
		t.Errorf("command = %q, want /usr/local/bin/sir guard evaluate", cmd)
	}
}

// TestClaudeAgent_DetectInstallation is a smoke test that returns without
// asserting anything specific: it only verifies the method runs.
func TestClaudeAgent_DetectInstallation(t *testing.T) {
	c := &ClaudeAgent{}
	_ = c.DetectInstallation() // smoke — may be true or false
	// ConfigPath must be non-empty unless UserHomeDir failed (very unlikely in tests).
	if c.ConfigPath() == "" {
		t.Skip("cannot determine home dir in this environment")
	}
}

// TestForID_Defaults asserts Claude is the default for empty / unknown IDs
// in the backward-compat-friendly sense: empty returns Claude; unknown non-
// empty returns nil.
func TestForID_Defaults(t *testing.T) {
	if ForID("") == nil {
		t.Error("ForID(\"\") = nil, want ClaudeAgent")
	}
	if ForID(Claude) == nil {
		t.Error("ForID(Claude) = nil, want ClaudeAgent")
	}
	if ForID("bogus") != nil {
		t.Error("ForID(bogus) != nil, want nil")
	}
	if ForID(Codex) == nil {
		t.Error("ForID(Codex) = nil, want CodexAgent")
	}
}

// TestClaudeFormatPostToolUseResponse_ReturnsNil pins Claude's PostToolUse
// wire contract: there is no stdout response (PostToolUse doesn't honor
// permissionDecision in Claude Code). If anyone changes Claude's adapter
// to emit JSON for PostToolUse, this test forces them to update
// pkg/hooks/post_evaluate.go's stderr fallback at the same time so
// non-allow decisions still reach the developer.
func TestClaudeFormatPostToolUseResponse_ReturnsNil(t *testing.T) {
	c := &ClaudeAgent{}
	for _, decision := range []string{"allow", "deny", "ask"} {
		b, err := c.FormatPostToolUseResponse(decision, "some reason")
		if err != nil {
			t.Errorf("FormatPostToolUseResponse(%q): unexpected error %v", decision, err)
		}
		if b != nil {
			t.Errorf("FormatPostToolUseResponse(%q) = %q, want nil", decision, b)
		}
	}
}
