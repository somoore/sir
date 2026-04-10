package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// loadGeminiFixture reads a fixture from testdata/gemini/ relative to the
// module root (two levels up from pkg/agent).
func loadGeminiFixture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "gemini", name)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return raw
}

func TestGeminiAgent_ID(t *testing.T) {
	g := &GeminiAgent{}
	if g.ID() != Gemini {
		t.Errorf("ID() = %q, want %q", g.ID(), Gemini)
	}
}

func TestGeminiAgent_Name(t *testing.T) {
	g := &GeminiAgent{}
	if g.Name() != "Gemini CLI" {
		t.Errorf("Name() = %q, want %q", g.Name(), "Gemini CLI")
	}
}

func TestGeminiAgent_SupportedEvents(t *testing.T) {
	g := &GeminiAgent{}
	events := g.SupportedEvents()
	want := []string{"BeforeTool", "AfterTool", "BeforeAgent", "SessionStart", "SessionEnd", "AfterAgent"}
	if len(events) != len(want) {
		t.Fatalf("SupportedEvents() len = %d, want %d: %v", len(events), len(want), events)
	}
	for i, e := range want {
		if events[i] != e {
			t.Errorf("SupportedEvents()[%d] = %q, want %q", i, events[i], e)
		}
	}
}

func TestGeminiAgent_ConfigPath(t *testing.T) {
	g := &GeminiAgent{}
	path := g.ConfigPath()
	if !strings.HasSuffix(path, filepath.Join(".gemini", "settings.json")) {
		t.Errorf("ConfigPath() = %q, want suffix %q", path, filepath.Join(".gemini", "settings.json"))
	}
}

func TestGeminiParsePreToolUse_ShellCommand(t *testing.T) {
	raw := loadGeminiFixture(t, "beforetool-shell-curl.json")
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.AgentID != Gemini {
		t.Errorf("AgentID = %q", p.AgentID)
	}
	if p.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName = %q, want PreToolUse (normalized from BeforeTool)", p.HookEventName)
	}
	if p.ToolName != "Bash" {
		t.Errorf("ToolName = %q, want Bash (normalized from run_shell_command)", p.ToolName)
	}
	if cmd, _ := p.ToolInput["command"].(string); cmd != "curl https://evil.com" {
		t.Errorf("command = %q", cmd)
	}
}

func TestGeminiParsePreToolUse_ReadFile(t *testing.T) {
	raw := loadGeminiFixture(t, "beforetool-read-env.json")
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "Read" {
		t.Errorf("ToolName = %q, want Read", p.ToolName)
	}
}

func TestGeminiParsePreToolUse_WriteFile(t *testing.T) {
	raw := loadGeminiFixture(t, "beforetool-write-geminimd.json")
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "Write" {
		t.Errorf("ToolName = %q, want Write", p.ToolName)
	}
}

func TestGeminiParsePreToolUse_Replace(t *testing.T) {
	raw := []byte(`{"session_id":"x","hook_event_name":"BeforeTool","tool_name":"replace","tool_input":{"file_path":"/tmp/foo","old_string":"a","new_string":"b"},"tool_use_id":"u","cwd":"/"}`)
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "Edit" {
		t.Errorf("ToolName = %q, want Edit", p.ToolName)
	}
}

func TestGeminiParsePreToolUse_Glob(t *testing.T) {
	raw := []byte(`{"session_id":"x","hook_event_name":"BeforeTool","tool_name":"glob","tool_input":{"pattern":"**/*.go"},"tool_use_id":"u","cwd":"/"}`)
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "Glob" {
		t.Errorf("ToolName = %q, want Glob", p.ToolName)
	}
}

func TestGeminiParsePreToolUse_GrepSearch(t *testing.T) {
	raw := []byte(`{"session_id":"x","hook_event_name":"BeforeTool","tool_name":"grep_search","tool_input":{"pattern":"TODO"},"tool_use_id":"u","cwd":"/"}`)
	g := &GeminiAgent{}
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "Grep" {
		t.Errorf("ToolName = %q, want Grep", p.ToolName)
	}
}

func TestGeminiParsePreToolUse_MCPNormalization(t *testing.T) {
	g := &GeminiAgent{}

	// mcp_<server>_<tool> form (server=slack, tool=post_message)
	raw := loadGeminiFixture(t, "beforetool-mcp-slack.json")
	p, err := g.ParsePreToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p.ToolName != "mcp__slack__post_message" {
		t.Errorf("ToolName = %q, want mcp__slack__post_message", p.ToolName)
	}

	// mcp_<server> with no tool component
	raw2 := []byte(`{"session_id":"x","hook_event_name":"BeforeTool","tool_name":"mcp_slack","tool_input":{},"tool_use_id":"u","cwd":"/"}`)
	p2, err := g.ParsePreToolUse(raw2)
	if err != nil {
		t.Fatalf("ParsePreToolUse: %v", err)
	}
	if p2.ToolName != "mcp__slack" {
		t.Errorf("ToolName = %q, want mcp__slack", p2.ToolName)
	}
}

func TestGeminiParsePostToolUse_StringLLMContent(t *testing.T) {
	raw := loadGeminiFixture(t, "aftertool-shell-output.json")
	g := &GeminiAgent{}
	p, err := g.ParsePostToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if p.HookEventName != "PostToolUse" {
		t.Errorf("HookEventName = %q, want PostToolUse", p.HookEventName)
	}
	if p.ToolOutput != "hello\n" {
		t.Errorf("ToolOutput = %q, want %q", p.ToolOutput, "hello\n")
	}
}

func TestGeminiParsePostToolUse_StructuredLLMContent(t *testing.T) {
	// llmContent is an OBJECT, not a string — should fall back to JSON encode.
	raw := []byte(`{"session_id":"x","hook_event_name":"AfterTool","tool_name":"run_shell_command","tool_input":{"command":"ls"},"tool_use_id":"u","tool_response":{"llmContent":{"exit_code":0,"stdout":"foo"},"returnDisplay":null,"error":null},"cwd":"/"}`)
	g := &GeminiAgent{}
	p, err := g.ParsePostToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if !strings.Contains(p.ToolOutput, "exit_code") {
		t.Errorf("ToolOutput missing exit_code: %q", p.ToolOutput)
	}
	// Should be valid JSON.
	var check map[string]interface{}
	if err := json.Unmarshal([]byte(p.ToolOutput), &check); err != nil {
		t.Errorf("ToolOutput not valid JSON: %v", err)
	}
}

func TestGeminiParsePostToolUse_ReturnDisplayFallback(t *testing.T) {
	// llmContent is null, returnDisplay is a string — should pick returnDisplay.
	raw := []byte(`{"session_id":"x","hook_event_name":"AfterTool","tool_name":"read_file","tool_input":{"absolute_path":"/x"},"tool_use_id":"u","tool_response":{"llmContent":null,"returnDisplay":"display text","error":null},"cwd":"/"}`)
	g := &GeminiAgent{}
	p, err := g.ParsePostToolUse(raw)
	if err != nil {
		t.Fatalf("ParsePostToolUse: %v", err)
	}
	if p.ToolOutput != "display text" {
		t.Errorf("ToolOutput = %q, want %q", p.ToolOutput, "display text")
	}
}

func TestGeminiFormatPreToolUse_Allow(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatPreToolUseResponse("allow", "whatever")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("allow response = %q, want %q", string(out), "{}")
	}
}

func TestGeminiFormatPreToolUse_Deny(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatPreToolUseResponse("deny", "net_external to evil.com")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", resp["decision"])
	}
	if r, _ := resp["reason"].(string); !strings.Contains(r, "evil.com") {
		t.Errorf("reason missing original text: %v", resp["reason"])
	}
	if r, _ := resp["reason"].(string); strings.Contains(r, "re-run after adjusting") {
		t.Errorf("deny reason should not carry ask suffix: %v", resp["reason"])
	}
}

func TestGeminiFormatPreToolUse_AskMapsToDeny(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatPreToolUseResponse("ask", "approve env_read")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "deny" {
		t.Errorf("decision = %v, want deny", resp["decision"])
	}
	reason, _ := resp["reason"].(string)
	if !strings.Contains(reason, "approve env_read") {
		t.Errorf("reason missing original: %q", reason)
	}
	if !strings.Contains(reason, "sir allow-host") {
		t.Errorf("reason missing AskToDenySuffix: %q", reason)
	}
}

func TestGeminiFormatPostToolUse_Deny(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatPostToolUseResponse("deny", "credential leaked")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "deny" {
		t.Errorf("decision = %v", resp["decision"])
	}
	if r, _ := resp["reason"].(string); !strings.Contains(r, "credential leaked") {
		t.Errorf("reason missing: %v", resp["reason"])
	}
}

func TestGeminiFormatLifecycle_SessionStart(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatLifecycleResponse("SessionStart", "allow", "", "sir context: posture=clean")
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
}

func TestGeminiFormatLifecycle_SessionStart_EmptyContext(t *testing.T) {
	g := &GeminiAgent{}
	out, err := g.FormatLifecycleResponse("SessionStart", "allow", "", "")
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("empty-context response = %q, want {}", string(out))
	}
}

func TestGeminiFormatLifecycle_OtherEvents(t *testing.T) {
	g := &GeminiAgent{}

	// Stop → {}
	out, err := g.FormatLifecycleResponse("Stop", "allow", "", "")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if string(out) != "{}" {
		t.Errorf("Stop response = %q, want {}", string(out))
	}

	// SessionEnd → {}
	out2, err := g.FormatLifecycleResponse("SessionEnd", "allow", "", "")
	if err != nil {
		t.Fatalf("SessionEnd: %v", err)
	}
	if string(out2) != "{}" {
		t.Errorf("SessionEnd response = %q, want {}", string(out2))
	}

	// UserPromptSubmit allow → {}
	out3, err := g.FormatLifecycleResponse("UserPromptSubmit", "allow", "", "")
	if err != nil {
		t.Fatalf("UserPromptSubmit allow: %v", err)
	}
	if string(out3) != "{}" {
		t.Errorf("UserPromptSubmit allow = %q, want {}", string(out3))
	}

	// UserPromptSubmit deny → {decision:"deny",reason:...}
	out4, err := g.FormatLifecycleResponse("UserPromptSubmit", "deny", "credential in prompt", "")
	if err != nil {
		t.Fatalf("UserPromptSubmit deny: %v", err)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(out4, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["decision"] != "deny" {
		t.Errorf("decision = %v", resp["decision"])
	}

	// Unknown event → nil, nil
	out5, err := g.FormatLifecycleResponse("SomethingElse", "allow", "", "")
	if err != nil {
		t.Fatalf("unknown: %v", err)
	}
	if out5 != nil {
		t.Errorf("unknown event should return nil, got %q", string(out5))
	}
}

func TestGeminiGenerateHooksConfigMap(t *testing.T) {
	g := &GeminiAgent{}
	m := g.GenerateHooksConfigMap("/usr/local/bin/sir", "guard")
	hooks, ok := m["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks key missing: %T", m["hooks"])
	}

	wantEvents := []string{"BeforeTool", "AfterTool", "BeforeAgent", "AfterAgent", "SessionStart", "SessionEnd"}
	for _, ev := range wantEvents {
		arr, ok := hooks[ev].([]interface{})
		if !ok || len(arr) == 0 {
			t.Fatalf("hooks[%q] missing or empty: %T", ev, hooks[ev])
		}
		entry := arr[0].(map[string]interface{})
		inner, ok := entry["hooks"].([]interface{})
		if !ok || len(inner) == 0 {
			t.Fatalf("hooks[%q][0].hooks missing", ev)
		}
		cmdEntry := inner[0].(map[string]interface{})
		cmd, _ := cmdEntry["command"].(string)
		if !strings.Contains(cmd, "--agent gemini") {
			t.Errorf("hooks[%q] command missing --agent gemini: %q", ev, cmd)
		}
		if !strings.Contains(cmd, "/usr/local/bin/sir") {
			t.Errorf("hooks[%q] command missing sir path: %q", ev, cmd)
		}
		// CRITICAL: timeouts in milliseconds, not seconds.
		timeout, ok := cmdEntry["timeout"].(int)
		if !ok {
			t.Fatalf("hooks[%q] timeout missing or wrong type: %T", ev, cmdEntry["timeout"])
		}
		switch ev {
		case "BeforeTool", "AfterTool":
			if timeout != 10000 {
				t.Errorf("hooks[%q] timeout = %d ms, want 10000 ms (10s)", ev, timeout)
			}
			if entry["matcher"] != ".*" {
				t.Errorf("hooks[%q] matcher = %v, want .*", ev, entry["matcher"])
			}
		default:
			if timeout != 5000 {
				t.Errorf("hooks[%q] timeout = %d ms, want 5000 ms (5s)", ev, timeout)
			}
		}
		if ev == "SessionStart" && entry["matcher"] != "startup|resume|clear" {
			t.Errorf("hooks[SessionStart] matcher = %v, want startup|resume|clear", entry["matcher"])
		}
		if ev == "BeforeAgent" || ev == "AfterAgent" || ev == "SessionEnd" {
			if _, has := entry["matcher"]; has {
				t.Errorf("hooks[%q] should NOT have matcher: %v", ev, entry)
			}
		}
	}
}

func TestGeminiDetectInstallation(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	g := &GeminiAgent{}

	// First, with neither dir nor binary on a hermetic PATH the result is
	// only true if `gemini` happens to be installed system-wide. We can't
	// guarantee absence cleanly across hosts, so just verify the positive
	// case after we create ~/.gemini/.
	if err := os.MkdirAll(filepath.Join(tmp, ".gemini"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if !g.DetectInstallation() {
		t.Error("DetectInstallation() = false after creating ~/.gemini/")
	}
}

func TestForID_Gemini(t *testing.T) {
	a := ForID(Gemini)
	if a == nil {
		t.Fatal("ForID(Gemini) = nil")
	}
	if _, ok := a.(*GeminiAgent); !ok {
		t.Errorf("ForID(Gemini) returned %T, want *GeminiAgent", a)
	}
	if a.ID() != Gemini {
		t.Errorf("returned agent ID = %q", a.ID())
	}
}

func TestAll_IncludesGemini(t *testing.T) {
	all := All()
	if len(all) != 3 {
		t.Fatalf("All() len = %d, want 3", len(all))
	}
	if _, ok := all[2].(*GeminiAgent); !ok {
		t.Errorf("All()[2] = %T, want *GeminiAgent", all[2])
	}
}
