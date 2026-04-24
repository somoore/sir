package hooks

import "strings"

// extractFilePath gets the file_path from tool input.
func extractFilePath(toolInput map[string]interface{}) string {
	if p, ok := toolInput["file_path"].(string); ok {
		return p
	}
	if p, ok := toolInput["path"].(string); ok {
		return p
	}
	return ""
}

func extractApplyPatchTargets(command string) []string {
	if !strings.Contains(command, "*** Begin Patch") {
		return nil
	}
	prefixes := []string{
		"*** Add File: ",
		"*** Update File: ",
		"*** Delete File: ",
	}
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(command, "\n") {
		line = strings.TrimSpace(line)
		for _, prefix := range prefixes {
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			target := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if target == "" {
				continue
			}
			if _, ok := seen[target]; ok {
				continue
			}
			seen[target] = struct{}{}
			out = append(out, target)
		}
	}
	return out
}

func extractPatchPayload(toolInput map[string]interface{}) string {
	for _, key := range []string{"command", "patch", "input", "content", "diff"} {
		if v, ok := toolInput[key].(string); ok {
			return v
		}
	}
	return ""
}

// extractCommand gets the command from tool input.
func extractCommand(toolInput map[string]interface{}) string {
	if c, ok := toolInput["command"].(string); ok {
		return c
	}
	return ""
}

// extractTarget gets a generic target identifier from tool input.
func extractTarget(toolInput map[string]interface{}) string {
	// Try common field names
	for _, key := range []string{"file_path", "path", "command", "url", "query", "pattern"} {
		if v, ok := toolInput[key].(string); ok {
			return v
		}
	}
	return ""
}
