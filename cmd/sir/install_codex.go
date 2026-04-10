package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

// init wires agent-specific post-install hooks into their specs. Kept in
// cmd/sir because ensureCodexFeatureFlag lives here — pulling it into
// pkg/agent would create a circular import with cmd/sir's helpers.
func init() {
	agent.NewCodexAgent().GetSpec().PostInstallFunc = func(homeDir string, skipPrompt bool) {
		codexConfigPath := filepath.Join(homeDir, ".codex", "config.toml")
		ensureCodexFeatureFlag(codexConfigPath, skipPrompt)
	}
}

// ensureCodexFeatureFlag checks ~/.codex/config.toml for
// `codex_hooks = true` under [features] and, if missing, asks the user
// whether to add it. When the flag is absent sir's hook commands still
// register but Codex won't actually fire them until the user enables the
// feature flag.
func ensureCodexFeatureFlag(configPath string, skipPrompt bool) {
	status, lines, err := codexHooksFlagStatus(configPath)
	switch status {
	case codexFlagAlreadyEnabled:
		return
	case codexFlagUnreadable:
		fmt.Fprintf(os.Stderr, "  WARNING: could not read %s: %v\n", configPath, err)
		fmt.Fprintln(os.Stderr, "  Codex hooks require `codex_hooks = true` under [features] in this file.")
		return
	case codexFlagMissingFile:
		fmt.Printf("  %s does not exist. Codex hooks require codex_hooks=true under [features].\n", configPath)
		if !skipPrompt && !promptYesNo("  Create it now? [y/N] ") {
			fmt.Println("  [ ] Skipped. Hooks are installed but will NOT fire until you enable codex_hooks=true.")
			return
		}
		if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not create %s dir: %v\n", filepath.Dir(configPath), err)
			return
		}
		body := "[features]\ncodex_hooks = true\n"
		if err := os.WriteFile(configPath, []byte(body), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not write %s: %v\n", configPath, err)
			return
		}
		fmt.Printf("  [x] Created %s with codex_hooks=true\n", configPath)
	case codexFlagNeedsEnable:
		fmt.Printf("  %s exists but codex_hooks is not enabled. Codex hooks require `codex_hooks = true` under [features].\n", configPath)
		if !skipPrompt && !promptYesNo("  Add/enable it now? [y/N] ") {
			fmt.Println("  [ ] Skipped. Hooks are installed but will NOT fire until you enable codex_hooks=true.")
			return
		}
		newLines := insertCodexHooksFlag(lines)
		out := strings.Join(newLines, "\n")
		if !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if err := os.WriteFile(configPath, []byte(out), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "  WARNING: could not write %s: %v\n", configPath, err)
			return
		}
		fmt.Printf("  [x] Enabled codex_hooks=true in %s\n", configPath)
	}
}

type codexFlagStatus int

const (
	codexFlagAlreadyEnabled codexFlagStatus = iota
	codexFlagNeedsEnable
	codexFlagMissingFile
	codexFlagUnreadable
)

// codexHooksFlagStatus inspects a Codex config.toml file (line-by-line
// without a TOML library) and reports whether codex_hooks=true is already
// set under [features]. Returns the file lines for in-place mutation when
// the flag needs to be added.
func codexHooksFlagStatus(path string) (codexFlagStatus, []string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return codexFlagMissingFile, nil, nil
		}
		return codexFlagUnreadable, nil, err
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		return codexFlagUnreadable, nil, err
	}

	inFeatures := false
	for _, raw := range lines {
		trim := strings.TrimSpace(raw)
		if strings.HasPrefix(trim, "#") || trim == "" {
			continue
		}
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			inFeatures = trim == "[features]"
			continue
		}
		if inFeatures && strings.HasPrefix(trim, "codex_hooks") {
			rest := strings.TrimSpace(strings.TrimPrefix(trim, "codex_hooks"))
			rest = strings.TrimPrefix(rest, "=")
			rest = strings.TrimSpace(rest)
			if i := strings.Index(rest, "#"); i >= 0 {
				rest = strings.TrimSpace(rest[:i])
			}
			if rest == "true" {
				return codexFlagAlreadyEnabled, lines, nil
			}
		}
	}
	return codexFlagNeedsEnable, lines, nil
}

// insertCodexHooksFlag returns a new line slice with codex_hooks=true
// inserted under an existing [features] section, or with [features] and
// the flag appended if no such section exists. Preserves all unrelated
// content verbatim.
func insertCodexHooksFlag(lines []string) []string {
	featuresIdx := -1
	for i, raw := range lines {
		trim := strings.TrimSpace(raw)
		if trim == "[features]" {
			featuresIdx = i
			break
		}
	}
	if featuresIdx < 0 {
		out := append([]string(nil), lines...)
		if len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		out = append(out, "[features]", "codex_hooks = true")
		return out
	}

	end := len(lines)
	for i := featuresIdx + 1; i < len(lines); i++ {
		trim := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trim, "[") && strings.HasSuffix(trim, "]") {
			end = i
			break
		}
	}
	for i := featuresIdx + 1; i < end; i++ {
		if strings.HasPrefix(strings.TrimSpace(lines[i]), "codex_hooks") {
			out := append([]string(nil), lines...)
			out[i] = "codex_hooks = true"
			return out
		}
	}
	out := append([]string(nil), lines[:featuresIdx+1]...)
	out = append(out, "codex_hooks = true")
	out = append(out, lines[featuresIdx+1:]...)
	return out
}

func promptYesNo(msg string) bool {
	fmt.Print(msg)
	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	return confirm == "y" || confirm == "yes"
}
