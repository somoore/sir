// sir — Sandbox in Reverse
// CLI entrypoint with subcommands for install, uninstall, status, support,
// doctor, ledger, explain, and guard (hook handlers).
package main

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// `sir <cmd> --help` must show help, never execute the command (a
	// destructive command like uninstall would otherwise start running).
	// Passthrough commands forward args to a subprocess, so skip them.
	if os.Args[1] != "help" && !passthroughCommands[os.Args[1]] && wantsHelp(os.Args[2:]) {
		printCommandHelp(os.Args[1])
		return
	}

	projectRoot, err := os.Getwd()
	if err != nil {
		fatal("cannot determine working directory: %v", err)
	}

	switch os.Args[1] {
	case "install":
		mode := "guard"
		for _, arg := range os.Args[2:] {
			switch arg {
			case "guard", "observe":
				mode = arg
			case "--observe":
				mode = "observe"
			case "--guard":
				mode = "guard"
			}
		}
		cmdInstall(projectRoot, mode)
	case "setup":
		cmdSetup(projectRoot, os.Args[2:])
	case "uninstall":
		cmdUninstall(projectRoot)
	case "status":
		cmdStatus(projectRoot, os.Args[2:]...)
	case "support":
		cmdSupport(os.Args[2:])
	case "capabilities":
		cmdCapabilities(os.Args[2:])
	case "posture":
		cmdPosture(projectRoot, os.Args[2:])
	case "doctor":
		cmdDoctor(projectRoot, os.Args[2:]...)
	case "approvals":
		cmdApprovals(projectRoot, os.Args[2:])
	case "log", "ledger":
		cmdLogLifecycle(projectRoot, os.Args[2:])
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
		cmdGuard(projectRoot, os.Args[2:])
	case "demo":
		cmdDemo()
	case "secret":
		cmdSecret(projectRoot, os.Args[2:])
	case "unlock", "reset":
		// `sir unlock` is the canonical name — it clears developer-recoverable
		// runtime restriction state (including secret-session locks and
		// prompt-driving transient taint). `sir reset` remains as a
		// compatibility alias for older docs and muscle memory. The old
		// `sir clear session` form has been removed: it was undocumented,
		// footgun-shaped, and duplicated `sir unlock` exactly.
		cmdClearSession(projectRoot)
	case "allow-host":
		cmdAllowHostArgs(projectRoot, os.Args[2:])
	case "allow-remote":
		if len(os.Args) < 3 {
			fatal("usage: sir allow-remote <remote-name> [--remove] [--yes]")
		}
		cmdAllowRemoteArgs(projectRoot, os.Args[2:])
	case "approve":
		cmdApprove(projectRoot, os.Args[2:])
	case "policy":
		cmdPolicy(projectRoot, os.Args[2:])
	case "config":
		// Memorable alias for the canonical config view.
		cmdPolicy(projectRoot, append([]string{"show"}, os.Args[2:]...))
	case "protect-path":
		cmdProtectPath(projectRoot, os.Args[2:])
	case "unprotect-path":
		cmdUnprotectPath(projectRoot, os.Args[2:])
	case "trust", "trust-mcp":
		if len(os.Args) < 3 {
			fatal("usage: sir trust host|remote|mcp|path <name> [--ttl D] [--remove] [--yes]")
		}
		cmdTrust(projectRoot, os.Args[2:])
	case "mcp":
		cmdMCP(projectRoot, os.Args[2:])
	case "mcp-proxy":
		if len(os.Args) < 3 {
			fatal("usage: sir mcp-proxy [--allow-host host]... [--no-sandbox] <command> [args...]\n\nWraps an MCP server with OS-level hardening.\nmacOS: localhost-only egress by default; any --allow-host broadens to general outbound access.\nLinux: network namespace isolation when unshare is available; --allow-host is not host-granular.\n\n--no-sandbox skips sandbox-exec entirely and runs in monitored mode (stderr\ncredential scanning + signal forwarding still active, no network/filesystem\nisolation). Use for MCP servers that XPC to a macOS .app and can't run under\nsandbox-exec. Helpers under /Applications/*.app/Contents/MacOS/ are\nauto-detected and degrade without this flag; --no-sandbox is the opt-out\nfor helpers at non-standard paths. When the proxy's working directory\nresolves to a known sir project, a ledger entry is appended so the\ndegradation is auditable in `sir log`; the stderr notice is emitted\nunconditionally.")
		}
		cmdMCPProxy(os.Args[2:])
	case "trace":
		cmdTrace(projectRoot)
	case "audit":
		if wantsFriction(os.Args[2:]) {
			cmdFriction(projectRoot, filterFlag(os.Args[2:], "--friction"))
		} else {
			cmdAudit(projectRoot)
		}
	case "friction":
		cmdFriction(projectRoot, os.Args[2:])
	case "replay":
		cmdReplay(projectRoot, os.Args[2:])
	case "run", "launch", "contain":
		cmdRun(projectRoot, os.Args[2:])
	case "relay":
		cmdRelay(os.Args[2:])
	case "completion":
		cmdCompletion(os.Args[2:])
	case "verify":
		cmdVerify()
	case "version":
		cmdVersion(os.Args[2:])
	case "update", "upgrade":
		// Update is a deliberate, non-self-modifying action for a security
		// tool: show current vs latest and the exact verified upgrade command.
		cmdVersion([]string{"--check"})
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
  sir setup [--strict|--default]  Guided first-run setup for policy + hooks
  sir install [--agent <id>] [--observe] [--no-rebaseline]
                                 Auto-detect installed agents and set up hooks
                                 (--agent: claude, codex, gemini)
                                 --observe records would_allow/ask/deny and
                                 detections without blocking (observe-only
                                 rollout); enable enforcement later without
                                 losing telemetry.
                                 --no-rebaseline skips refreshing posture
                                 baselines in other project sessions. Default
                                 behavior refreshes them so sessions that were
                                 alive across the upgrade do not wedge into
                                 deny-all. Use only if you need a per-project
                                 'sir doctor' pass for auditing.
  sir status [--json]            Show whether sir is active and what it sees
  sir support --json             Emit the public support manifests as JSON
  sir capabilities [--json]      Show per-agent support and hook coverage
  sir posture [--json]           Show install, policy, MCP, runtime, ledger posture
  sir demo                       Run a 60-second tour of what sir blocks

When sir asks or blocks
  sir why                        Explain the most recent decision
  sir approvals [--json]         Show pending asks, retry grants, and trust approvals
  sir approve --last             Turn the last ask into a scoped, expiring lease
                                 (host/remote/MCP); --once for a single retry
  sir unlock                     Clear transient runtime restrictions, restore operability
  sir secret view <path>         Show a sensitive file's keys with values redacted
  sir trust host <h> [--ttl 2h]      Allow a host          (--remove to revoke)
  sir trust remote <name>            Allow a git remote    (--remove to revoke)
  sir trust mcp <server>             Trust an MCP server with credentials (--remove)
  sir trust path <p> [--posture]     Mark a path sensitive (--remove to unprotect)
                                     (aliases: allow-host, allow-remote, protect-path)

Policy
  sir policy show                Show this project's lease and policy profile
  sir policy diff --strict       Compare the active lease with strict defaults
  sir policy init --profile P    Initialize a policy profile (personal|team|strict)
                                 team/strict deny raw secret reads (use sir secret view)
  sir policy suggest [--json]    Recommend safer scoped leases from observed sessions
  sir protect-path <path>        Add a sensitive path pattern
  sir unprotect-path <path>      Remove a sensitive path pattern

Review a session
  sir audit                      One-screen security summary of this session
  sir friction [--json]          Summarize prompts, blocks, noisy rules, and scoped-lease suggestions
  sir replay [--profile strict]  Project ledger decisions under another policy profile
  sir trace                      Export this session's ledger as a shareable HTML timeline
  sir log [verify|archive|export] Show, verify, archive, or export the decision log
  sir log --follow               Live-stream decisions as the agent works
  sir explain [--last|--index N] Explain any decision with full causal chain
  sir mcp [status]               Inspect discovered MCP servers and their runtime posture
  sir mcp wrap [--yes]           Rewrite raw command-based MCP servers through sir mcp-proxy
  sir mcp scope <name> [flags]   Add per-server MCP capability scopes

Maintenance
  sir doctor [--json]            Check sir's health and auto-repair (--json: read-only probe for CI)
  sir verify                     Verify binary integrity against install-time manifest
  sir uninstall [--agent <id>]   Remove sir hooks from one or all installed agents
  sir update                     Check for a newer release and show the upgrade command
  sir version [--check]          Show sir's version (--check compares with GitHub Releases)
  sir completion bash|zsh|fish   Print a shell completion script

	Advanced
	  sir relay [--addr :8787]       Run the central Slack relay (dedup, digest, buttons)
	  sir mcp-proxy <command>        Wrap an MCP server with OS-level MCP hardening
	  sir run <agent>               Host-agent containment launcher
	  sir launch <agent>            Alias for sir run
	  sir contain <agent>           Alias for sir run`)
}
