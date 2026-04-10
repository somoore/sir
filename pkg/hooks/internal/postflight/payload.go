package postflight

import "github.com/somoore/sir/pkg/agent"

func ExtractTarget(payload *agent.HookPayload) string {
	if payload == nil {
		return ""
	}
	if p, ok := payload.ToolInput["file_path"].(string); ok {
		return p
	}
	if p, ok := payload.ToolInput["path"].(string); ok {
		return p
	}
	return ""
}

func SourceRef(payload *agent.HookPayload, fallback string) string {
	if payload == nil {
		return fallback
	}
	if payload.ToolUseID != "" {
		return payload.ToolUseID
	}
	if fallback != "" {
		return fallback
	}
	return payload.ToolName
}

func SensitiveTarget(payload *agent.HookPayload, isSensitivePath func(string) bool, isEnvCommand func(string) bool) string {
	if payload == nil {
		return ""
	}
	switch payload.ToolName {
	case "Read", "Grep":
		target := ExtractTarget(payload)
		if target != "" && isSensitivePath(target) {
			return target
		}
	case "Bash":
		if cmd, ok := payload.ToolInput["command"].(string); ok && isEnvCommand(cmd) {
			return cmd
		}
	}
	return ""
}
