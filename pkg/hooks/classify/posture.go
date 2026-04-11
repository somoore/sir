package classify

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

// IsSirSelfCommand reports whether the command mutates sir's own posture.
func IsSirSelfCommand(cmd string) bool {
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
		"clear":        true,
		"reset":        true,
		"unlock":       true,
		"allow-host":   true,
		"allow-remote": true,
		"trust-mcp":    true,
		"trust":        true,
	}
	return protectedSubcommands[strings.ToLower(parts[1])]
}

// ContainsSirSelfCommand checks every segment of a compound shell command.
func ContainsSirSelfCommand(cmd string) bool {
	for _, seg := range SplitCompoundCommand(cmd) {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		norm := NormalizeCommand(seg)
		if norm == "" {
			norm = seg
		}
		if IsSirSelfCommand(norm) {
			return true
		}
	}
	return false
}

// TargetsSirStateFiles reports whether a command appears to target sir-owned state.
func TargetsSirStateFiles(cmd string) bool {
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

// IsPostureDeleteOrLink checks whether rm/ln targets posture files or ~/.sir state.
func IsPostureDeleteOrLink(cmd string, l *lease.Lease) bool {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 2 {
		return false
	}

	lower0 := strings.ToLower(parts[0])
	sirDir := globalSirDir()

	if lower0 == "rm" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if sirDir != "" {
				expanded := os.ExpandEnv(arg)
				if expanded == sirDir || strings.HasPrefix(expanded, sirDir+string(filepath.Separator)) {
					return true
				}
				if arg == "~/.sir" || strings.HasPrefix(arg, "~/.sir/") {
					return true
				}
			}
			if IsPostureFileResolved(arg, l) {
				return true
			}
		}
	}

	if lower0 == "ln" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if IsPostureFileResolved(arg, l) {
				return true
			}
		}
	}

	return false
}

func globalSirDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".sir")
}
