// sir — Sandbox in Reverse
// CLI entrypoint with subcommands for install, uninstall, status, doctor,
// ledger, explain, and guard (hook handlers).
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
)

// parseAgentFlag scans guard-subcommand arguments for --agent <value> or
// --agent=<value> and returns the identifier, defaulting to "claude" when
// the flag is absent. Accepts any position in args so the flag can appear
// after the subcommand (e.g. "sir guard evaluate --agent codex").
//
// Backward compatibility: existing installs have hook commands like
// "sir guard evaluate" with no --agent flag. Those continue to work because
// the default is "claude".
func parseAgentFlag(args []string) string {
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
	return string(agent.Claude)
}

// resolveAgent looks up an adapter by ID and falls back to Claude for
// unknown or empty IDs. Returns the adapter and a boolean indicating whether
// the requested ID was recognized — callers can use this to emit a warning
// for unknown agents without breaking the existing deny-fast behavior.
func resolveAgent(id string) (agent.Agent, bool) {
	ag := agent.ForID(agent.AgentID(id))
	if ag == nil {
		return agent.ForID(agent.Claude), false
	}
	return ag, true
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	projectRoot, err := os.Getwd()
	if err != nil {
		fatal("cannot determine working directory: %v", err)
	}

	switch os.Args[1] {
	case "install":
		mode := "guard"
		for _, arg := range os.Args[2:] {
			if arg == "guard" || arg == "observe" {
				mode = arg
			}
		}
		cmdInstall(projectRoot, mode)
	case "uninstall":
		cmdUninstall(projectRoot)
	case "status":
		cmdStatus(projectRoot)
	case "doctor":
		cmdDoctor(projectRoot)
	case "log", "ledger":
		verify := len(os.Args) > 2 && os.Args[2] == "verify"
		cmdLog(projectRoot, verify)
	case "explain", "why":
		index := -1 // default: last entry
		for i, arg := range os.Args[2:] {
			if arg == "--last" {
				index = -1
			} else if arg == "--index" && i+1 < len(os.Args[2:]) {
				index, _ = strconv.Atoi(os.Args[2:][i+1])
			}
		}
		cmdExplain(projectRoot, index)
	case "guard":
		// Resolve the host-agent adapter from --agent. Default "claude" keeps
		// backward compatibility with existing installs whose hook commands
		// do not pass --agent.
		agentID := string(agent.Claude)
		if len(os.Args) > 3 {
			agentID = parseAgentFlag(os.Args[3:])
		}
		ag, known := resolveAgent(agentID)
		if !known {
			guardDeny(ag, "sir guard: unknown --agent value: %q", agentID)
		}
		if len(os.Args) < 3 {
			guardDeny(ag, "sir guard: missing subcommand (evaluate|post-evaluate|user-prompt|subagent-start|compact-reinject|config-change|instructions-loaded|session-summary|session-end|elicitation)")
		}
		switch os.Args[2] {
		case "evaluate":
			if err := hooks.Evaluate(projectRoot, ag); err != nil {
				guardDeny(ag, "sir guard evaluate: %v", err)
			}
		case "post-evaluate":
			// PostToolUse should never silently fail-open on unreadable state.
			if err := hooks.PostEvaluate(projectRoot, ag); err != nil {
				guardPostDeny(ag, "sir guard post-evaluate: %v", err)
			}
		case "user-prompt":
			// UserPromptSubmit — advance turn counter
			if err := hooks.EvaluateUserPrompt(projectRoot, ag); err != nil {
				guardLifecycleDeny(ag, "UserPromptSubmit", "sir guard user-prompt: %v", err)
			}
		case "subagent-start":
			// SubagentStart — check delegation policy
			if err := hooks.EvaluateSubagentStart(projectRoot, ag); err != nil {
				guardDeny(ag, "sir guard subagent-start: %v", err)
			}
		case "compact-reinject":
			// SessionStart (compact) — reinject security reminders
			if err := hooks.EvaluateCompactReinject(projectRoot, ag); err != nil {
				fmt.Fprintf(os.Stderr, "sir: compact-reinject error: %v\n", err)
			}
		case "config-change":
			// ConfigChange — log and verify posture
			if err := hooks.EvaluateConfigChange(projectRoot, ag); err != nil {
				guardLifecycleDeny(ag, "ConfigChange", "sir guard config-change: %v", err)
			}
		case "instructions-loaded":
			// InstructionsLoaded — hash instructions for tamper detection
			if err := hooks.EvaluateInstructionsLoaded(projectRoot, ag); err != nil {
				guardLifecycleDeny(ag, "InstructionsLoaded", "sir guard instructions-loaded: %v", err)
			}
		case "session-summary":
			// Stop — compute and log session summary
			if err := hooks.EvaluateSessionSummary(projectRoot, ag); err != nil {
				guardLifecycleDeny(ag, "Stop", "sir guard session-summary: %v", err)
			}
		case "session-end":
			// SessionEnd — finalize session
			if err := hooks.EvaluateSessionEnd(projectRoot, ag); err != nil {
				guardLifecycleDeny(ag, "SessionEnd", "sir guard session-end: %v", err)
			}
		case "elicitation":
			// Elicitation hook: scan for credential harvesting.
			if err := hooks.EvaluateElicitation(projectRoot, ag); err != nil {
				fmt.Fprintf(os.Stderr, "sir: elicitation error: %v\n", err)
			}
		default:
			guardDeny(ag, "sir guard: unknown subcommand: %s", os.Args[2])
		}
	case "demo":
		cmdDemo()
	case "unlock", "reset":
		// `sir unlock` is the canonical name — it lifts the secret-session
		// lock and restores external network access. `sir reset` remains as
		// a compatibility alias for older docs and muscle memory. The old
		// `sir clear session` form has been removed: it was undocumented,
		// footgun-shaped, and duplicated `sir unlock` exactly.
		cmdClearSession(projectRoot)
	case "allow-host":
		if len(os.Args) < 3 {
			fatal("usage: sir allow-host <hostname>")
		}
		cmdAllowHost(projectRoot, os.Args[2])
	case "allow-remote":
		if len(os.Args) < 3 {
			fatal("usage: sir allow-remote <remote-name>")
		}
		cmdAllowRemote(projectRoot, os.Args[2])
	case "trust", "trust-mcp":
		if len(os.Args) < 3 {
			fatal("usage: sir trust <server-name>")
		}
		cmdTrustMCP(projectRoot, os.Args[2])
	case "mcp":
		cmdMCP(projectRoot, os.Args[2:])
	case "mcp-proxy":
		if len(os.Args) < 3 {
			fatal("usage: sir mcp-proxy [--allow-host host]... <command> [args...]\n\nWraps an MCP server with OS-level hardening.\nmacOS: localhost-only egress by default; any --allow-host broadens to general outbound access.\nLinux: network namespace isolation when unshare is available; --allow-host is not host-granular.")
		}
		cmdMCPProxy(os.Args[2:])
	case "trace":
		cmdTrace(projectRoot)
	case "audit":
		cmdAudit(projectRoot)
	case "run":
		cmdRun(projectRoot, os.Args[2:])
	case "version":
		cmdVersion(os.Args[2:])
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`sir — sandbox in reverse
A security runtime for AI coding agents (Claude Code, Codex, and Gemini CLI).
Invisible during normal work. Loud at the exits.

Get started
  sir install [--agent <id>]     Auto-detect installed agents and set up hooks
                                 (--agent: claude, codex, gemini)
  sir status                     Show whether sir is active and what it sees
  sir demo                       Run a 60-second tour of what sir blocks

When sir asks or blocks
  sir why                        Explain the most recent decision
  sir unlock                     Lift the secret-session lock, restore network access
  sir allow-host <hostname>      Permanently allow requests to a host
  sir allow-remote <name>        Permanently allow pushes to a git remote
  sir trust <mcp-server>         Trust an MCP server with credentials (rare)

Review a session
  sir audit                      One-screen security summary of this session
  sir trace                      Export this session's ledger as a shareable HTML timeline
  sir log [verify]               Show or verify the full decision log
  sir explain [--last|--index N] Explain any decision with full causal chain
  sir mcp [status]               Inspect discovered MCP servers and their runtime posture
  sir mcp wrap [--yes]           Rewrite raw command-based MCP servers through sir mcp-proxy

Maintenance
  sir doctor                     Check sir's health and auto-repair
  sir uninstall [--agent <id>]   Remove sir hooks from one or all installed agents
  sir version [--check]          Show sir's version (--check compares with GitHub Releases)

	Advanced
	  sir mcp-proxy <command>        Wrap an MCP server with OS-level MCP hardening
	  sir run <agent>               Experimental host-agent containment (macOS proxy sandbox, Linux exact-destination namespace allowlist)`)
}
