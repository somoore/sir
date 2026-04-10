package hooks

import (
	"os"
	"path/filepath"
)

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

// globalSirDir returns the absolute path to ~/.sir so we can protect it from
// deletion or hardlinking by isPostureDeleteOrLink. Returns empty string if
// the home directory cannot be determined.
func globalSirDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sir")
}
