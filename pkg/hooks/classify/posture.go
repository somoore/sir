package classify

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

// IsSirSelfCommand reports whether the command mutates sir's own posture.
//
// The default is deny for any mutating verb. Read-only subcommands are
// explicitly allow-listed, so a future subcommand that writes lease/session
// state is treated as self-modification without another edit here. (A plain
// deny-list previously missed `approve`, `policy init`, `protect-path`,
// `unprotect-path`, `mcp approve`, `guard`, and `doctor`.)
func IsSirSelfCommand(cmd string) bool {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 2 {
		return false
	}
	if strings.ToLower(parts[0]) != "sir" {
		return false
	}
	sub := strings.ToLower(parts[1])
	action := ""
	if len(parts) >= 3 {
		action = strings.ToLower(parts[2])
	}
	switch sub {
	case "mcp":
		switch action {
		case "", "status", "list", "show", "inspect":
			return false
		}
		return true
	case "policy":
		switch action {
		case "", "show", "diff", "suggest":
			return false
		}
		return true
	case "log", "ledger":
		// Reading/verifying/exporting the audit trail does not widen
		// authority; archiving can truncate the live chain.
		return action == "archive"
	case "doctor":
		// `--json` is the read-only CI probe; the repairing form
		// re-baselines posture hashes and clears deny-all.
		for _, p := range parts[2:] {
			if p == "--json" {
				return false
			}
		}
		return true
	}
	protectedSubcommands := map[string]bool{
		"install":        true,
		"setup":          true,
		"uninstall":      true,
		"clear":          true,
		"reset":          true,
		"unlock":         true,
		"allow-host":     true,
		"allow-remote":   true,
		"trust-mcp":      true,
		"trust":          true,
		"approve":        true,
		"protect-path":   true,
		"unprotect-path": true,
		"guard":          true,
	}
	return protectedSubcommands[sub]
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
		"install": true, "truncate": true, "unlink": true, "touch": true,
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
			if IsPostureFileResolved(arg, l) || IsSirControlPlanePath(arg) {
				return true
			}
		}
	}

	if lower0 == "ln" {
		for _, arg := range parts[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			if IsPostureFileResolved(arg, l) || IsSirControlPlanePath(arg) {
				return true
			}
		}
	}

	return false
}

// IsSirControlPlanePath reports whether target is the sir state tree
// (~/.sir, or the SIR_STATE_HOME override), the sir/mister-core binary, or
// the installed binary paths. These are the files the agent would have to
// rewrite to disable or replace enforcement, so Write/Edit to them must be
// posture-gated even when a project's lease predates these entries.
func IsSirControlPlanePath(target string) bool {
	if target == "" {
		return false
	}
	p := strings.TrimSpace(target)
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, strings.TrimPrefix(p, "~"))
		}
	}
	if !filepath.IsAbs(p) {
		return false
	}
	p = filepath.Clean(p)
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(p)); err == nil {
		p = filepath.Join(resolved, filepath.Base(p))
	}

	var roots []string
	if home, err := os.UserHomeDir(); err == nil {
		roots = append(roots,
			filepath.Join(home, ".sir"),
			filepath.Join(home, ".local", "bin", "sir"),
			filepath.Join(home, ".local", "bin", "mister-core"),
		)
	}
	if override := strings.TrimSpace(os.Getenv("SIR_STATE_HOME")); override != "" {
		roots = append(roots, filepath.Join(override, ".sir"))
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exe); err == nil {
			roots = append(roots, resolved)
		}
		roots = append(roots, exe)
	}
	for _, root := range roots {
		root = filepath.Clean(root)
		if root == "" || root == "." {
			continue
		}
		if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
			return true
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
