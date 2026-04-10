package postflight

import (
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func TestExtractTarget(t *testing.T) {
	payload := &agent.HookPayload{
		ToolInput: map[string]interface{}{"file_path": ".env"},
	}
	if got := ExtractTarget(payload); got != ".env" {
		t.Fatalf("ExtractTarget(file_path) = %q, want %q", got, ".env")
	}

	payload = &agent.HookPayload{
		ToolInput: map[string]interface{}{"path": "config.json"},
	}
	if got := ExtractTarget(payload); got != "config.json" {
		t.Fatalf("ExtractTarget(path) = %q, want %q", got, "config.json")
	}
}

func TestSourceRef(t *testing.T) {
	payload := &agent.HookPayload{ToolName: "Read", ToolUseID: "tool-123"}
	if got := SourceRef(payload, "fallback"); got != "tool-123" {
		t.Fatalf("SourceRef(tool use id) = %q, want %q", got, "tool-123")
	}

	payload = &agent.HookPayload{ToolName: "Read"}
	if got := SourceRef(payload, "fallback"); got != "fallback" {
		t.Fatalf("SourceRef(fallback) = %q, want %q", got, "fallback")
	}
	if got := SourceRef(payload, ""); got != "Read" {
		t.Fatalf("SourceRef(tool name) = %q, want %q", got, "Read")
	}
}

func TestSensitiveTarget(t *testing.T) {
	isSensitivePath := func(target string) bool { return target == ".env" }
	isEnvCommand := func(cmd string) bool { return cmd == "env" }

	readPayload := &agent.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": ".env"},
	}
	if got := SensitiveTarget(readPayload, isSensitivePath, isEnvCommand); got != ".env" {
		t.Fatalf("SensitiveTarget(read) = %q, want %q", got, ".env")
	}

	bashPayload := &agent.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "env"},
	}
	if got := SensitiveTarget(bashPayload, isSensitivePath, isEnvCommand); got != "env" {
		t.Fatalf("SensitiveTarget(bash) = %q, want %q", got, "env")
	}
}
