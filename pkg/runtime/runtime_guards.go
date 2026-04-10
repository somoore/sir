package runtime

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

type runWriteGuards struct {
	literals []string
	subpaths []string
}

func newRunWriteGuards() runWriteGuards {
	return runWriteGuards{
		literals: make([]string, 0, 16),
		subpaths: make([]string, 0, 8),
	}
}

func addRunWriteGuard(path string, seen map[string]struct{}, dst *[]string) {
	if path == "" {
		return
	}
	for _, clean := range runGuardTargets(path) {
		if _, ok := seen[clean]; ok {
			continue
		}
		seen[clean] = struct{}{}
		*dst = append(*dst, clean)
	}
}

func runGuardTargets(path string) []string {
	if path == "" {
		return nil
	}
	targets := []string{filepath.Clean(path)}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		resolved = filepath.Clean(resolved)
		if resolved != targets[0] {
			targets = append(targets, resolved)
		}
	}
	return targets
}

func sortRunWriteGuards(guards *runWriteGuards) {
	sort.Strings(guards.literals)
	sort.Strings(guards.subpaths)
}

func runProtectedWriteGuards(projectRoot string) (runWriteGuards, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return runWriteGuards{}, err
	}
	literalsSeen := map[string]struct{}{}
	subpathsSeen := map[string]struct{}{}
	guards := newRunWriteGuards()
	addLiteral := func(path string) { addRunWriteGuard(path, literalsSeen, &guards.literals) }
	addSubpath := func(path string) { addRunWriteGuard(path, subpathsSeen, &guards.subpaths) }

	for _, rel := range []string{".claude", ".gemini", ".codex"} {
		addSubpath(filepath.Join(homeDir, rel))
	}
	for _, ag := range agent.All() {
		spec := ag.GetSpec()
		if spec == nil {
			continue
		}
		if spec.ConfigFile != "" {
			addLiteral(filepath.Join(homeDir, spec.ConfigFile))
		}
		if spec.ConfigStrategy.CanonicalBackupFile != "" {
			addLiteral(spec.ConfigStrategy.CanonicalBackupPath(homeDir))
		}
	}
	addLiteral(filepath.Join(homeDir, ".codex", "config.toml"))
	addSubpath(filepath.Join(homeDir, ".sir", "projects"))
	for _, rel := range []string{".mcp.json", "CLAUDE.md", "GEMINI.md", "AGENTS.md"} {
		addLiteral(filepath.Join(projectRoot, rel))
	}

	sortRunWriteGuards(&guards)
	return guards, nil
}

func runProtectedWriteGuardsForAgent(projectRoot string, ag agent.Agent) (runWriteGuards, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return runWriteGuards{}, err
	}
	literalsSeen := map[string]struct{}{}
	subpathsSeen := map[string]struct{}{}
	guards := newRunWriteGuards()
	addLiteral := func(path string) { addRunWriteGuard(path, literalsSeen, &guards.literals) }
	addSubpath := func(path string) { addRunWriteGuard(path, subpathsSeen, &guards.subpaths) }

	spec := ag.GetSpec()
	if spec != nil {
		if len(spec.ConfigDirs) > 0 {
			for _, rel := range spec.ConfigDirs {
				addSubpath(filepath.Join(homeDir, rel))
			}
		} else if spec.ConfigFile != "" {
			if first := strings.Split(filepath.Clean(spec.ConfigFile), string(filepath.Separator))[0]; first != "" && first != "." {
				addSubpath(filepath.Join(homeDir, first))
			}
		}
		if spec.ConfigFile != "" {
			addLiteral(filepath.Join(homeDir, spec.ConfigFile))
		}
		if spec.ConfigStrategy.CanonicalBackupFile != "" {
			addLiteral(spec.ConfigStrategy.CanonicalBackupPath(homeDir))
		}
	}

	if ag != nil && ag.ID() == agent.AgentID("codex") {
		addLiteral(filepath.Join(homeDir, ".codex", "config.toml"))
	}

	addSubpath(filepath.Join(homeDir, ".sir", "projects"))
	for _, rel := range runProjectPostureFilesForAgent(ag) {
		addLiteral(filepath.Join(projectRoot, rel))
	}

	sortRunWriteGuards(&guards)
	return guards, nil
}

func runProjectPostureFilesForAgent(ag agent.Agent) []string {
	files := []string{".mcp.json"}
	if ag == nil {
		return files
	}
	switch ag.ID() {
	case agent.AgentID("claude"):
		files = append(files, "CLAUDE.md")
	case agent.AgentID("gemini"):
		files = append(files, "GEMINI.md")
	case agent.AgentID("codex"):
		files = append(files, "AGENTS.md")
	}
	return files
}
