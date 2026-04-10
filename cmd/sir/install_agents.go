package main

import (
	"os"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

func supportedAgentIDs() string {
	ids := make([]string, 0, len(agent.Registry()))
	for _, reg := range agent.Registry() {
		ids = append(ids, string(reg.ID))
	}
	return strings.Join(ids, ", ")
}

func mustHomeDir() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fatal("get home dir: %v", err)
	}
	return homeDir
}

// parseInstallAgentFlag scans install/uninstall args for --agent <id> or
// --agent=<id>. Unlike parseAgentFlag (cmd/sir/main.go) which defaults to
// "claude" for guard dispatch, this variant returns "" when the flag is
// absent so the install path can auto-detect all available agents.
func parseInstallAgentFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--agent" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "--agent=") {
			return strings.TrimPrefix(a, "--agent=")
		}
	}
	return ""
}

type installOptions struct {
	explicitAgent string
	skipPreview   bool
}

func parseInstallOptions(args []string) installOptions {
	opts := installOptions{}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--yes":
			opts.skipPreview = true
		case a == "--agent" && i+1 < len(args):
			opts.explicitAgent = args[i+1]
			i++
		case strings.HasPrefix(a, "--agent="):
			opts.explicitAgent = strings.TrimPrefix(a, "--agent=")
		}
	}
	return opts
}

func mcpScopesForAgent(explicitAgent string) map[mcpConfigScope]bool {
	if explicitAgent == "" {
		return nil
	}
	switch agent.AgentID(explicitAgent) {
	case agent.Claude:
		return map[mcpConfigScope]bool{mcpConfigClaudeGlobal: true}
	case agent.Gemini:
		return map[mcpConfigScope]bool{mcpConfigGeminiGlobal: true}
	default:
		return map[mcpConfigScope]bool{}
	}
}

// selectAgentsForInstall resolves the set of agents to operate on for
// install based on the --agent flag.
//
// Rules:
//  1. If --agent is given, use exactly that one adapter. Fail-closed if the
//     adapter is unknown or not detected on this machine — never silently
//     fall back to a different agent.
//  2. Otherwise, Claude Code is always included (backward compatibility:
//     sir install on a fresh machine has always created ~/.claude/settings.json
//     whether or not Claude was already "detected"). Codex is additionally
//     included if detected. This means the pre-Phase-3 behavior is
//     preserved exactly when only Claude is present, and the multi-agent
//     path is opportunistically engaged when Codex is also on the box.
func selectAgentsForInstall(explicit string) []agent.Agent {
	if explicit != "" {
		ag := agent.ForID(agent.AgentID(explicit))
		if ag == nil {
			fatal("unknown agent: %s (supported: %s)", explicit, supportedAgentIDs())
		}
		if !ag.DetectInstallation() {
			fatal("--agent %s requested but %s is not installed on this machine.\n  Install %s first, then re-run sir install.", explicit, ag.Name(), ag.Name())
		}
		return []agent.Agent{ag}
	}
	var agents []agent.Agent
	for _, reg := range agent.Registry() {
		ag := reg.New()
		if reg.ID == agent.Claude || ag.DetectInstallation() {
			agents = append(agents, ag)
		}
	}
	return agents
}
