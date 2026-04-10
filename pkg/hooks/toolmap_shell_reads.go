package hooks

import (
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

var sensitiveReadPrograms = map[string]bool{
	"cat":     true,
	"tac":     true,
	"nl":      true,
	"head":    true,
	"tail":    true,
	"less":    true,
	"more":    true,
	"bat":     true,
	"batcat":  true,
	"xxd":     true,
	"hexdump": true,
	"od":      true,
	"sed":     true,
	"awk":     true,
	"gawk":    true,
	"grep":    true,
	"rg":      true,
	"ag":      true,
	"ack":     true,
	"strings": true,
	"file":    true,
}

var readProgramFlagsTakingValue = map[string]map[string]bool{
	"cat":     {},
	"tac":     {"s": true},
	"nl":      {"b": true, "d": true, "f": true, "h": true, "i": true, "l": true, "n": true, "p": true, "s": true, "v": true, "w": true},
	"head":    {"c": true, "n": true, "q": true},
	"tail":    {"c": true, "n": true, "F": true},
	"less":    {"b": true, "h": true, "j": true, "k": true, "o": true, "p": true, "t": true, "T": true, "x": true, "y": true, "z": true, "#": true},
	"more":    {"n": true, "p": true, "t": true},
	"bat":     {"l": true, "H": true, "r": true, "m": true, "p": true, "theme": true},
	"batcat":  {"l": true, "H": true, "r": true, "m": true, "p": true},
	"xxd":     {"c": true, "g": true, "l": true, "o": true, "s": true},
	"hexdump": {"e": true, "f": true, "n": true, "s": true},
	"od":      {"A": true, "j": true, "N": true, "S": true, "t": true, "w": true},
	"sed":     {"e": true, "f": true, "i": true},
	"awk":     {"F": true, "f": true, "v": true},
	"gawk":    {"F": true, "f": true, "v": true},
	"grep":    {"A": true, "B": true, "C": true, "D": true, "d": true, "e": true, "f": true, "m": true},
	"rg":      {"A": true, "B": true, "C": true, "e": true, "f": true, "g": true, "t": true, "T": true, "m": true, "max-count": true, "before-context": true, "after-context": true, "context": true, "regexp": true},
	"ag":      {"A": true, "B": true, "C": true, "G": true, "g": true, "m": true},
	"ack":     {"A": true, "B": true, "C": true, "g": true, "m": true},
	"strings": {"n": true, "t": true, "e": true},
	"file":    {"m": true, "P": true},
}

// detectSensitiveFileRead checks whether cmd is a shell read-command invoked
// against a sensitive path. Returns (resolvedSensitivePath, true) on hit so
// the caller can populate Intent.Target with the actual file, or ("", false)
// if no sensitive positional is found.
func detectSensitiveFileRead(cmd string, l *lease.Lease) (string, bool) {
	normalized := normalizeCommand(strings.TrimSpace(cmd))
	if normalized == "" {
		return "", false
	}
	fields := strings.Fields(normalized)
	if len(fields) < 2 {
		return "", false
	}
	program := strings.ToLower(fields[0])
	if !sensitiveReadPrograms[program] {
		return "", false
	}
	valueFlags := readProgramFlagsTakingValue[program]

	skipNext := false
	for _, arg := range fields[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(arg, "--") {
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) >= 2 {
			flagBody := arg[1:]
			if flagBody == "-" {
				continue
			}
			if len(flagBody) == 1 && valueFlags[flagBody] {
				skipNext = true
				continue
			}
			if valueFlags[string(flagBody[0])] {
				continue
			}
			continue
		}
		if IsSensitivePathResolved(arg, l) {
			return arg, true
		}
	}
	return "", false
}
