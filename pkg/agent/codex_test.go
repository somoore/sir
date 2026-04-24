package agent

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// loadCodexFixture reads a fixture from testdata/codex/ relative to the
// module root (two levels up from pkg/agent).
func loadCodexFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "codex", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func TestCodexAgent_Metadata(t *testing.T) {
	c := &CodexAgent{}
	if c.ID() != Codex {
		t.Errorf("ID() = %q, want %q", c.ID(), Codex)
	}
	if c.Name() != "Codex" {
		t.Errorf("Name() = %q, want %q", c.Name(), "Codex")
	}
	events := c.SupportedEvents()
	want := []string{"PreToolUse", "PermissionRequest", "PostToolUse", "UserPromptSubmit", "SessionStart", "Stop"}
	if len(events) != len(want) {
		t.Fatalf("SupportedEvents() len = %d, want %d: %v", len(events), len(want), events)
	}
	for i, e := range want {
		if events[i] != e {
			t.Errorf("SupportedEvents()[%d] = %q, want %q", i, events[i], e)
		}
	}
	if path := c.ConfigPath(); !strings.HasSuffix(path, filepath.Join(".codex", "hooks.json")) {
		t.Errorf("ConfigPath() = %q, want suffix %q", path, filepath.Join(".codex", "hooks.json"))
	}
}

func TestCodexAgent_ParsePreToolUse(t *testing.T) {
	raw := loadCodexFixture(t, "pretooluse-bash-curl.json")
	c := &CodexAgent{}
	p, err := c.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.AgentID != Codex {
		t.Errorf("AgentID = %q, want %q", p.AgentID, Codex)
	}
	if p.SessionID == "" {
		t.Error("SessionID empty")
	}
	if p.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q", p.HookEventName)
	}
	if p.ToolName != "Bash" {
		t.Errorf("ToolName = %q", p.ToolName)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "curl https://evil.com" {
		t.Errorf("command = %q", cmd)
	}
	if p.ToolUseID == "" {
		t.Error("ToolUseID empty")
	}
	if p.CWD != "/Users/dev/myproject" {
		t.Errorf("CWD = %q", p.CWD)
	}
}

func TestCodexAgent_ParsePostToolUse_StringResponse(t *testing.T) {
	raw := loadCodexFixture(t, "posttooluse-bash-string-output.json")
	c := &CodexAgent{}
	p, err := c.ParsePostToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if p.ToolOutput != "hello\n" {
		t.Errorf("ToolOutput = %q, want %q", p.ToolOutput, "hello\n")
	}
	if p.AgentID != Codex {
		t.Errorf("AgentID = %q", p.AgentID)
	}
}

func TestCodexAgent_ParsePostToolUse_StructuredResponse(t *testing.T) {
	raw := loadCodexFixture(t, "posttooluse-bash-structured-output.json")
	c := &CodexAgent{}
	p, err := c.ParsePostToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	// Structured tool_response should be stringified JSON.
	if !strings.Contains(p.ToolOutput, "\"exit_code\"") {
		t.Errorf("ToolOutput missing exit_code: %q", p.ToolOutput)
	}
	if !strings.Contains(p.ToolOutput, "\"combined_output\"") {
		t.Errorf("ToolOutput missing combined_output: %q", p.ToolOutput)
	}
	// Confirm it's valid JSON.
	var check map[string]interface{}
	if err := json.Unmarshal([]byte(p.ToolOutput), &check); err != nil {
		t.Errorf("ToolOutput not valid JSON: %v", err)
	}
}

func TestCodexAgent_FormatPreToolUseResponse_Allow(t *testing.T) {
	c := &CodexAgent{}
	out, err := c.FormatPreToolUseResponse("allow", "whatever")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("allow response = %q, want %q", string(out), "{}")
	}
}

func TestCodexAgent_FormatPreToolUseResponse_Deny(t *testing.T) {
	c := &CodexAgent{}
	out, err := c.FormatPreToolUseResponse("deny", "net_external to evil.com")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "block" {
		t.Errorf("decision = %v, want block", resp["decision"])
	}
	if !strings.Contains(resp["reason"].(string), "evil.com") {
		t.Errorf("reason missing original text: %v", resp["reason"])
	}
	if strings.Contains(resp["reason"].(string), "re-run after adjusting") {
		t.Errorf("deny reason should not carry ask suffix: %v", resp["reason"])
	}
}

func TestCodexAgent_FormatPreToolUseResponse_Ask_MapsToBlock(t *testing.T) {
	c := &CodexAgent{}
	out, err := c.FormatPreToolUseResponse("ask", "approve env_read")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "block" {
		t.Errorf("decision = %v, want block", resp["decision"])
	}
	reason, _ := resp["reason"].(string)
	if !strings.Contains(reason, "approve env_read") {
		t.Errorf("reason missing original: %q", reason)
	}
	if !strings.Contains(reason, "sir allow-host") {
		t.Errorf("reason missing ask suffix: %q", reason)
	}
}

func TestCodexAgent_FormatPostToolUseResponse_Deny(t *testing.T) {
	c := &CodexAgent{}
	out, err := c.FormatPostToolUseResponse("deny", "credential leaked")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "block" {
		t.Errorf("decision = %v", resp["decision"])
	}
	if r, _ := resp["reason"].(string); !strings.Contains(r, "credential leaked") {
		t.Errorf("top-level reason missing: %v", resp["reason"])
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput missing or wrong type: %T", resp["hookSpecificOutput"])
	}
	if hso["hookEventName"] != "PostToolUse" {
		t.Errorf("hookEventName = %v", hso["hookEventName"])
	}
	if ac, _ := hso["additionalContext"].(string); !strings.Contains(ac, "credential leaked") {
		t.Errorf("additionalContext missing reason: %v", hso["additionalContext"])
	}
}

func TestCodexAgent_FormatLifecycleResponse_SessionStart(t *testing.T) {
	c := &CodexAgent{}

	// With context: returns hookSpecificOutput envelope.
	out, err := c.FormatLifecycleResponse("SessionStart", "allow", "", "sir context: posture=clean")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hso, ok := resp["hookSpecificOutput"].(map[string]interface{})
	if !ok {
		t.Fatalf("hookSpecificOutput missing: %v", resp)
	}
	if hso["hookEventName"] != "SessionStart" {
		t.Errorf("hookEventName = %v", hso["hookEventName"])
	}
	if hso["additionalContext"] != "sir context: posture=clean" {
		t.Errorf("additionalContext = %v", hso["additionalContext"])
	}

	// Without context: empty object.
	out2, err := c.FormatLifecycleResponse("SessionStart", "allow", "", "")
	if err != nil {
		t.Fatalf("Format (empty ctx): %v", err)
	}
	if string(out2) != "{}" {
		t.Errorf("empty-context response = %q, want {}", string(out2))
	}
}

func TestCodexAgent_FormatLifecycleResponse_Stop(t *testing.T) {
	c := &CodexAgent{}

	// Block decision produces a continuation request.
	out, err := c.FormatLifecycleResponse("Stop", "block", "session tainted — cannot stop", "")
	if err != nil {
		t.Fatalf("Format Stop block: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "block" {
		t.Errorf("decision = %v", resp["decision"])
	}
	if r, _ := resp["reason"].(string); !strings.Contains(r, "tainted") {
		t.Errorf("reason = %v", resp["reason"])
	}

	// Allow → {}.
	out2, err := c.FormatLifecycleResponse("Stop", "allow", "", "")
	if err != nil {
		t.Fatalf("Format Stop allow: %v", err)
	}
	if string(out2) != "{}" {
		t.Errorf("allow response = %q, want {}", string(out2))
	}

	// UserPromptSubmit → {}.
	out3, _ := c.FormatLifecycleResponse("UserPromptSubmit", "allow", "", "")
	if string(out3) != "{}" {
		t.Errorf("UserPromptSubmit response = %q, want {}", string(out3))
	}
}

func TestCodexAgent_GenerateHooksConfig_Shape(t *testing.T) {
	c := &CodexAgent{}
	raw, err := c.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("GenerateHooksConfig: %v", err)
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hooks, ok := parsed["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("top-level hooks missing or wrong type: %T", parsed["hooks"])
	}

	// Each supported event must be present.
	for _, ev := range []string{"PreToolUse", "PermissionRequest", "PostToolUse", "SessionStart", "UserPromptSubmit", "Stop"} {
		arr, ok := hooks[ev].([]interface{})
		if !ok || len(arr) == 0 {
			t.Fatalf("hooks[%q] missing or empty: %T", ev, hooks[ev])
		}
		entry, ok := arr[0].(map[string]interface{})
		if !ok {
			t.Fatalf("hooks[%q][0] wrong type: %T", ev, arr[0])
		}
		inner, ok := entry["hooks"].([]interface{})
		if !ok || len(inner) == 0 {
			t.Fatalf("hooks[%q][0].hooks missing: %v", ev, entry)
		}
		cmdEntry := inner[0].(map[string]interface{})
		cmd, _ := cmdEntry["command"].(string)
		if !strings.Contains(cmd, "--agent codex") {
			t.Errorf("hooks[%q] command missing --agent codex: %q", ev, cmd)
		}
		if !strings.Contains(cmd, "/usr/local/bin/sir") {
			t.Errorf("hooks[%q] command missing sir path: %q", ev, cmd)
		}

		// Matcher presence rules.
		switch ev {
		case "PreToolUse", "PostToolUse":
			wantMatcher := "Bash|apply_patch|Edit|Write|mcp__.*"
			if entry["matcher"] != wantMatcher {
				t.Errorf("hooks[%q] matcher = %v, want %s", ev, entry["matcher"], wantMatcher)
			}
		case "PermissionRequest":
			if entry["matcher"] != ".*" {
				t.Errorf("hooks[PermissionRequest] matcher = %v, want .*", entry["matcher"])
			}
		case "SessionStart":
			if entry["matcher"] != "startup|resume" {
				t.Errorf("hooks[SessionStart] matcher = %v, want startup|resume", entry["matcher"])
			}
		case "UserPromptSubmit", "Stop":
			if _, has := entry["matcher"]; has {
				t.Errorf("hooks[%q] should NOT have matcher: %v", ev, entry)
			}
		}
	}

	// Codex-unsupported events must NOT be present.
	for _, ev := range []string{"SubagentStart", "ConfigChange", "InstructionsLoaded", "Elicitation", "SessionEnd"} {
		if _, has := hooks[ev]; has {
			t.Errorf("hooks[%q] must not be emitted for Codex", ev)
		}
	}
}

func TestCodexAgent_GenerateHooksConfigMap_RoundTrip(t *testing.T) {
	c := &CodexAgent{}
	m := mustHooksConfigMap(t, c, "/usr/local/bin/sir", "guard")
	fromMap, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal map: %v", err)
	}
	fromBytes, err := c.GenerateHooksConfig("/usr/local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("GenerateHooksConfig: %v", err)
	}
	// Canonicalize via unmarshal+marshal to avoid key-order flakes (Go
	// map marshaling is already stable but be explicit).
	var a, b interface{}
	_ = json.Unmarshal(fromMap, &a)
	_ = json.Unmarshal(fromBytes, &b)
	ca, _ := json.Marshal(a)
	cb, _ := json.Marshal(b)
	if string(ca) != string(cb) {
		t.Errorf("map and bytes differ:\n  map  : %s\n  bytes: %s", ca, cb)
	}
}

func TestCodexAgent_DetectInstallation(t *testing.T) {
	c := &CodexAgent{}
	// Smoke test: skip unless something on the host indicates Codex.
	home, _ := os.UserHomeDir()
	_, errDir := os.Stat(filepath.Join(home, ".codex"))
	_, errBin := exec.LookPath("codex")
	if errDir != nil && errBin != nil {
		t.Skip("neither ~/.codex nor codex binary present; skipping")
	}
	if !c.DetectInstallation() {
		t.Error("DetectInstallation() = false despite Codex signals present")
	}
}

func TestForID_Codex(t *testing.T) {
	a := ForID(Codex)
	if a == nil {
		t.Fatal("ForID(Codex) = nil")
	}
	if _, ok := a.(*CodexAgent); !ok {
		t.Errorf("ForID(Codex) returned %T, want *CodexAgent", a)
	}
	if a.ID() != Codex {
		t.Errorf("returned agent ID = %q", a.ID())
	}
}

func TestAll_IncludesCodex(t *testing.T) {
	all := All()
	if len(all) < 2 {
		t.Fatalf("All() len = %d, want >= 2", len(all))
	}
	if _, ok := all[0].(*ClaudeAgent); !ok {
		t.Errorf("All()[0] = %T, want *ClaudeAgent", all[0])
	}
	if _, ok := all[1].(*CodexAgent); !ok {
		t.Errorf("All()[1] = %T, want *CodexAgent", all[1])
	}
}
