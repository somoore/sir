package main

import (
	"fmt"
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

func detectInstalledAgents() []agent.Agent {
	var agents []agent.Agent
	for _, reg := range agent.Registry() {
		ag := reg.New()
		if ag.DetectInstallation() {
			agents = append(agents, ag)
		}
	}
	return agents
}

// selectAgentsForInstall resolves the set of agents to operate on for install
// based on the --agent flag.
//
// Rules:
//  1. If --agent is given, use exactly that one adapter. Fail-closed if the
//     adapter is unknown or not detected on this machine — never silently
//     fall back to a different agent.
//  2. Otherwise, auto-detect the supported agents already present on this
//     machine in deterministic registry order. If nothing is detected, return
//     an operator-facing error instead of silently manufacturing a Claude-only
//     install surface that the docs never promised.
func selectAgentsForInstall(explicit string) ([]agent.Agent, error) {
	if explicit != "" {
		ag := agent.ForID(agent.AgentID(explicit))
		if ag == nil {
			return nil, fmt.Errorf("unknown agent: %s (supported: %s)", explicit, supportedAgentIDs())
		}
		if !ag.DetectInstallation() {
			return nil, fmt.Errorf("--agent %s requested but %s is not installed on this machine.\n  Install %s first, then re-run sir install.", explicit, ag.Name(), ag.Name())
		}
		return []agent.Agent{ag}, nil
	}
	agents := detectInstalledAgents()
	if len(agents) == 0 {
		return nil, fmt.Errorf("no supported agents detected on this machine.\n  Install Claude Code, Gemini CLI, or Codex, then re-run sir install.\n  To pin one surface explicitly later, use --agent <%s> once that agent is present.", supportedAgentIDs())
	}
	return agents, nil
}
