package hooks

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// extractPackageName parses an install command to extract the package name.
// Returns empty string if no specific package is named (e.g., plain "npm install").
// Flags that take a value argument (e.g. pip's -r, -c, -t) skip their value too,
// so "pip install -r requirements.txt" does not misread "requirements.txt" as a package.
func extractPackageName(cmd string, manager string) string {
	parts := strings.Fields(cmd)
	pastVerb := false
	installVerbs := map[string]bool{"install": true, "add": true, "get": true, "i": true}

	// Flags whose next argument is a value (not a package name), per manager.
	// These prevent, e.g., "-r requirements.txt" from returning "requirements.txt".
	valuedFlags := map[string]bool{
		// pip: -r/--requirement, -c/--constraint, -t/--target, -d/--download,
		//      -i/--index-url, --extra-index-url, -e/--editable
		"-r": true, "--requirement": true,
		"-c": true, "--constraint": true,
		"-t": true, "--target": true,
		"-d": true, "--download": true,
		"-i": true, "--index-url": true,
		"--extra-index-url": true,
		"-e":                true, "--editable": true,
		// npm/yarn: --prefix, --workspace, -w, --tag
		"--prefix":    true,
		"--workspace": true,
		"-w":          true,
		"--tag":       true,
		// cargo: --features, --git, --branch, --rev, --path
		// (--target already listed above for pip)
		"--features": true,
		"--git":      true,
		"--branch":   true,
		"--rev":      true,
		"--path":     true,
	}

	skipNext := false
	for _, p := range parts {
		if skipNext {
			skipNext = false
			continue
		}
		if !pastVerb {
			if installVerbs[strings.ToLower(p)] {
				pastVerb = true
			}
			continue
		}
		if strings.HasPrefix(p, "-") {
			if valuedFlags[p] {
				skipNext = true
			}
			continue
		}
		// Strip version specifiers: foo==1.2.3, foo>=1, foo@1.2.3, foo^1, foo~1
		name := p
		for _, sep := range []string{"==", ">=", "<=", "~=", "@", "^", "~"} {
			if idx := strings.Index(name, sep); idx > 0 {
				name = name[:idx]
			}
		}
		if name == "" {
			continue
		}
		return name
	}
	return ""
}

// isPackageInLockfile checks whether a package name appears in the project lockfile.
// Returns true if found (allow) or if no lockfile exists (skip check, allow).
// Returns false only if the lockfile EXISTS but the package is NOT in it.
func isPackageInLockfile(projectRoot, manager, pkgName string) bool {
	lockfiles := LockfileForManager(manager)
	foundAnyLockfile := false
	lower := strings.ToLower(pkgName)

	for _, lf := range lockfiles {
		path := filepath.Join(projectRoot, lf)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		foundAnyLockfile = true
		content := string(data)

		switch manager {
		case "npm", "yarn", "pnpm", "bun":
			if strings.Contains(content, "\""+pkgName+"\"") ||
				strings.Contains(content, "'"+pkgName+"'") {
				return true
			}
		case "pip", "uv", "poetry":
			for _, line := range strings.Split(content, "\n") {
				trimmed := strings.TrimSpace(strings.ToLower(line))
				if strings.HasPrefix(trimmed, lower+"==") ||
					strings.HasPrefix(trimmed, lower+">=") ||
					strings.HasPrefix(trimmed, lower+"<=") ||
					strings.HasPrefix(trimmed, lower+"~=") ||
					trimmed == lower {
					return true
				}
			}
			// Also check pyproject.toml style: name = "pkgname"
			if strings.Contains(strings.ToLower(content), "\""+lower+"\"") {
				return true
			}
		case "cargo":
			if strings.Contains(content, "name = \""+pkgName+"\"") {
				return true
			}
		case "go":
			if strings.Contains(content, pkgName+" ") {
				return true
			}
		case "gem":
			if strings.Contains(content, "  "+pkgName+" (") ||
				strings.Contains(content, pkgName+" (") {
				return true
			}
		}
	}

	// No lockfile found → greenfield project, skip check
	if !foundAnyLockfile {
		return true
	}
	return false
}

// IsInstallCommand checks if a command is a package install command.
// Returns (isInstall, packageManager).
func IsInstallCommand(cmd string) (bool, string) {
	trimmed := strings.TrimSpace(cmd)
	lower := strings.ToLower(trimmed)

	// Note: npx is NOT an install command. It is handled separately as run_ephemeral.
	installPrefixes := []struct {
		prefix  string
		manager string
	}{
		{"pip install ", "pip"},
		{"pip3 install ", "pip"},
		{"python -m pip install ", "pip"},
		{"python3 -m pip install ", "pip"},
		{"npm install ", "npm"},
		{"npm i ", "npm"},
		{"yarn add ", "yarn"},
		{"pnpm add ", "pnpm"},
		{"bun add ", "bun"},
		{"cargo add ", "cargo"},
		{"go get ", "go"},
		{"gem install ", "gem"},
		{"uv add ", "uv"},
		{"poetry add ", "poetry"},
	}

	for _, ip := range installPrefixes {
		// Match "npm install foo" (prefix with trailing space) and
		// bare "npm install" (exact match without trailing space).
		bare := strings.TrimRight(ip.prefix, " ")
		if strings.HasPrefix(lower, ip.prefix) || lower == bare {
			return true, ip.manager
		}
	}
	return false, ""
}

// LockfileForManager returns the lockfile paths for a given package manager.
func LockfileForManager(manager string) []string {
	switch manager {
	case "pip":
		return []string{"requirements.txt", "requirements-dev.txt", "Pipfile.lock"}
	case "npm":
		return []string{"package-lock.json"}
	case "yarn":
		return []string{"yarn.lock"}
	case "pnpm":
		return []string{"pnpm-lock.yaml"}
	case "bun":
		return []string{"bun.lockb"}
	case "cargo":
		return []string{"Cargo.lock"}
	case "go":
		return []string{"go.sum"}
	case "gem":
		return []string{"Gemfile.lock"}
	case "uv":
		return []string{"uv.lock", "requirements.txt"}
	case "poetry":
		return []string{"poetry.lock"}
	default:
		return nil
	}
}

// DiffLockfile compares two lockfile contents and returns added/changed lines.
// This is a simple line-level diff, not a semantic package diff.
func DiffLockfile(before, after string) []string {
	beforeLines := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(before))
	for scanner.Scan() {
		beforeLines[scanner.Text()] = true
	}

	var added []string
	scanner = bufio.NewScanner(strings.NewReader(after))
	for scanner.Scan() {
		line := scanner.Text()
		if !beforeLines[line] && strings.TrimSpace(line) != "" {
			added = append(added, line)
		}
	}
	return added
}
