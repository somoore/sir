package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

type mcpCommandOptions struct {
	explicitAgent string
	skipPrompt    bool
}

func parseMCPCommandOptions(args []string) mcpCommandOptions {
	opts := mcpCommandOptions{}
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--yes":
			opts.skipPrompt = true
		case a == "--agent" && i+1 < len(args):
			opts.explicitAgent = args[i+1]
			i++
		case strings.HasPrefix(a, "--agent="):
			opts.explicitAgent = strings.TrimPrefix(a, "--agent=")
		}
	}
	return opts
}

func cmdMCP(projectRoot string, args []string) {
	subcmd := "status"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		subcmd = args[0]
		args = args[1:]
	}

	opts := parseMCPCommandOptions(args)
	if opts.explicitAgent != "" && agent.ForID(agent.AgentID(opts.explicitAgent)) == nil {
		fatal("unknown agent: %s (supported: %s)", opts.explicitAgent, supportedAgentIDs())
	}

	switch subcmd {
	case "status", "inventory":
		cmdMCPStatus(projectRoot, opts.explicitAgent)
	case "wrap":
		cmdMCPWrap(projectRoot, opts.explicitAgent, opts.skipPrompt)
	default:
		fatal("usage: sir mcp [status|inventory|wrap] [--agent <id>] [--yes]\n\nExamples:\n  sir mcp\n  sir mcp wrap --yes\n  sir mcp status --agent gemini")
	}
}

func cmdMCPStatus(projectRoot, explicitAgent string) {
	scopes := mcpScopesForAgent(explicitAgent)
	if explicitAgent != "" && len(scopes) == 0 {
		fmt.Println("sir mcp status")
		fmt.Println()
		fmt.Printf("  %s does not expose a supported MCP config surface in sir today.\n", explicitAgent)
		return
	}
	report := discoverMCPInventoryForScopes(projectRoot, scopes)

	fmt.Println("sir mcp status")
	fmt.Println()
	if explicitAgent != "" {
		fmt.Printf("  Scope: %s\n", explicitAgent)
	}
	if len(report.Servers) == 0 && len(report.Errors) == 0 {
		if explicitAgent != "" {
			fmt.Println("  No MCP servers found in that agent-scoped config surface.")
		} else {
			fmt.Println("  No MCP servers found in .mcp.json, ~/.claude/settings.json, or ~/.gemini/settings.json.")
		}
		return
	}

	printMCPStatus(report)
	if hasRawMCPServers(report.Servers) {
		fmt.Println("  Raw command-based MCP servers are still present.")
		fmt.Println("  Run 'sir mcp wrap' to rewrite them through sir mcp-proxy.")
	}
	if hasMalformedMCPServers(report.Servers) {
		fmt.Println("  Malformed sir mcp-proxy wrappers need manual inspection before sir can assess them safely.")
	}
}

func cmdMCPWrap(projectRoot, explicitAgent string, skipPrompt bool) {
	scopes := mcpScopesForAgent(explicitAgent)
	if explicitAgent != "" && len(scopes) == 0 {
		fmt.Println("sir mcp wrap")
		fmt.Println()
		fmt.Printf("  %s does not expose a supported MCP config surface in sir today.\n", explicitAgent)
		return
	}
	report := discoverMCPInventoryForScopes(projectRoot, scopes)
	for _, invErr := range report.Errors {
		fmt.Printf("warning: could not parse %s: %v\n", invErr.Path, invErr.Err)
	}

	planned := planMCPProxyRewrites(report.Servers)
	if len(planned) == 0 {
		fmt.Println("sir mcp wrap")
		fmt.Println()
		if len(report.Errors) > 0 {
			fmt.Println("  No readable raw command-based MCP servers were found.")
			fmt.Println("  One or more MCP config files could not be parsed, so sir cannot confirm the remaining MCP surfaces are clean.")
			return
		}
		fmt.Println("  No raw command-based MCP servers need wrapping.")
		if hasMalformedMCPServers(report.Servers) {
			fmt.Println("  Note: malformed sir mcp-proxy wrappers still require manual inspection.")
		}
		return
	}

	if !skipPrompt {
		fmt.Println("sir mcp wrap will:")
		for _, line := range renderMCPRewritePreview(planned) {
			fmt.Println(line)
		}
		fmt.Println()
		fmt.Print("Wrap these MCP servers with sir mcp-proxy? [Y/n] ")

		var confirm string
		if _, err := fmt.Scanln(&confirm); err != nil {
			fmt.Println()
			fmt.Println("MCP wrap cancelled (no interactive confirmation received). Re-run with --yes to skip the prompt.")
			return
		}
		confirm = strings.TrimSpace(strings.ToLower(confirm))
		if confirm == "n" || confirm == "no" {
			fmt.Println("MCP wrap cancelled.")
			return
		}
	}

	results, err := rewriteDiscoveredMCPServers(report.Servers, sirBinaryPath)
	if err != nil {
		fatal("rewrite MCP servers through sir mcp-proxy: %v", err)
	}

	fmt.Println("sir mcp wrap")
	fmt.Println()
	for _, result := range results {
		fmt.Printf("  Rewrote %s  (wrapped %s)\n", result.Path, strings.Join(result.Servers, ", "))
	}
	if len(report.Errors) > 0 {
		fmt.Println()
		fmt.Println("  Note: unreadable MCP config files were skipped. Fix them and re-run 'sir mcp status' to verify the remaining surfaces.")
	}
	fmt.Println()
	fmt.Println("Run 'sir mcp status' to verify MCP runtime posture.")
}

func renderMCPRewritePreview(servers []mcpServerInventory) []string {
	if len(servers) == 0 {
		return nil
	}
	byPath := make(map[string][]string)
	labels := make(map[string]string)
	for _, server := range servers {
		byPath[server.SourcePath] = append(byPath[server.SourcePath], server.Name)
		labels[server.SourcePath] = server.SourceLabel
	}

	paths := make([]string, 0, len(byPath))
	for path := range byPath {
		paths = append(paths, path)
	}
	sort.Strings(paths)

	lines := make([]string, 0, len(paths))
	for _, path := range paths {
		names := byPath[path]
		sort.Strings(names)
		label := labels[path]
		if label == "" {
			label = path
		}
		lines = append(lines, fmt.Sprintf("  Rewrite %s  (wrap %s)", label, strings.Join(names, ", ")))
	}
	return lines
}

func hasRawMCPServers(servers []mcpServerInventory) bool {
	for _, server := range servers {
		if server.RuntimeAssessment().Mode == mcpRuntimeRaw {
			return true
		}
	}
	return false
}

func hasMalformedMCPServers(servers []mcpServerInventory) bool {
	for _, server := range servers {
		if server.Proxy.Malformed {
			return true
		}
	}
	return false
}
