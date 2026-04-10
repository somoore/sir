package hooks

import (
	"path/filepath"
	"strings"
)

// isSirSelfCommand returns true when the command modifies sir itself.
// Prevents an agent from silently running "sir uninstall" to remove hook protection.
// "sir install", "sir uninstall", "sir clear session", and "sir reset" are gated.
// "sir status", "sir doctor", "sir log", "sir explain", "sir version" are informational and allowed.
func isSirSelfCommand(cmd string) bool {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 2 {
		return false
	}
	if strings.ToLower(parts[0]) != "sir" {
		return false
	}
	if strings.ToLower(parts[1]) == "mcp" {
		return len(parts) >= 3 && strings.ToLower(parts[2]) == "wrap"
	}
	protectedSubcommands := map[string]bool{
		"install":      true,
		"uninstall":    true,
		"clear":        true, // covers "sir clear session" (legacy alias)
		"reset":        true, // legacy alias for "sir unlock"
		"unlock":       true, // canonical name for lifting secret-session lock
		"allow-host":   true,
		"allow-remote": true,
		"trust-mcp":    true, // legacy alias
		"trust":        true, // prevents agent from self-trusting MCP servers
	}
	return protectedSubcommands[strings.ToLower(parts[1])]
}

// containsSirSelfCommand splits a compound command on shell operators (|, &&, ||, ;)
// and returns true if ANY segment contains a sir self-modification command.
func containsSirSelfCommand(cmd string) bool {
	segments := splitCompoundCommand(cmd)
	for _, seg := range segments {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		norm := normalizeCommand(seg)
		if norm == "" {
			norm = seg
		}
		if isSirSelfCommand(norm) {
			return true
		}
	}
	return false
}

// targetsSirStateFiles returns true when the command appears to target ~/.sir/ state files
// using tools like sed, awk, perl, python, chmod, chown, mv, cp, tee, dd.
func targetsSirStateFiles(cmd string) bool {
	lower := strings.ToLower(cmd)
	hasSirRef := strings.Contains(lower, "/.sir/") ||
		strings.Contains(lower, "session.json") ||
		strings.Contains(lower, "lease.json") ||
		strings.Contains(lower, "hooks-canonical.json") ||
		strings.Contains(lower, "/.claude/settings.json")

	if !hasSirRef {
		return false
	}
	if strings.Contains(lower, " > ") || strings.Contains(lower, " >> ") {
		return true
	}

	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		return false
	}
	base := strings.ToLower(filepath.Base(parts[0]))
	modifyingCommands := map[string]bool{
		"sed": true, "awk": true, "perl": true,
		"python": true, "python3": true, "python2": true,
		"ruby": true, "node": true,
		"chmod": true, "chown": true, "mv": true, "cp": true,
		"tee": true, "dd": true, "rm": true, "ln": true,
		"cat": true, "echo": true, "printf": true,
	}
	return modifyingCommands[base]
}
