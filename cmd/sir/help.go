package main

import "fmt"

// passthroughCommands forward their trailing args to a subprocess or read them
// from stdin, so a trailing --help may belong to the wrapped command, not sir.
// We never intercept --help for these.
var passthroughCommands = map[string]bool{
	"mcp-proxy": true,
	"run":       true,
	"launch":    true,
	"contain":   true,
	"guard":     true,
}

// commandHelp is concise per-command help shown for `sir <cmd> --help`. Keeping
// it here means `--help` never executes a (possibly destructive) command.
var commandHelp = map[string]string{
	"install":      "sir install [--agent claude|codex|gemini] [--observe] [--no-rebaseline]\n  Set up sir hooks for installed agents.\n  --observe records would_allow/ask/deny without blocking (observe-only rollout).",
	"uninstall":    "sir uninstall [--agent claude|codex|gemini]\n  Remove sir hooks from one or all agents. State under ~/.sir is preserved for\n  forensic review. To also remove binaries and all state, run uninstall.sh.",
	"setup":        "sir setup [--personal|--team|--strict] [--yes]\n  Guided first-run: choose a policy profile, then install hooks.",
	"status":       "sir status [--json] [--agents]\n  Show whether sir is active and what it currently sees.",
	"doctor":       "sir doctor [--json]\n  Diagnose sir's health and auto-repair (clears deny-all, restores baselines).",
	"verify":       "sir verify\n  Verify binary integrity against the install-time manifest.",
	"version":      "sir version [--check]\n  Show sir's version. --check compares with the latest GitHub release.",
	"update":       "sir update\n  Check for a newer release and print the exact, verified upgrade command.\n  It does not self-modify the binary (a deliberate choice for a security tool).",
	"explain":      "sir explain [--last | --index N]\n  Explain a decision with its full causal chain and recovery options.",
	"why":          "sir why\n  Explain the most recent decision (alias for `sir explain --last`).",
	"approve":      "sir approve --last [--once|--session|--ttl <dur>]\n  Turn the last ask into a scoped, expiring lease.\n  sir approve host|remote|mcp|path <x>   explicit grant",
	"unlock":       "sir unlock\n  Clear transient runtime restrictions (secret-session lock) and restore operability.",
	"allow-host":   "sir allow-host <host> [--ttl <dur>] [--remove] [--yes]\n  Allow (or with --remove, revoke) network egress to a host.",
	"allow-remote": "sir allow-remote <name> [--remove] [--yes]\n  Allow (or revoke) pushes to a git remote.",
	"trust":        "sir trust <mcp-server> [--remove] [--yes]\n  Trust (or revoke) an MCP server for credential-bearing args. Rare.",
	"secret":       "sir secret view <path> [--json]\n  Show a sensitive file's keys with values redacted.",
	"policy":       "sir policy [show|diff|init|suggest|protect-path|unprotect-path]\n  Inspect and configure this project's policy lease.",
	"config":       "sir config [--json]\n  Show this project's policy/lease and how to change it (alias for `sir policy show`).",
	"mcp":          "sir mcp [status|wrap|approve|revoke|list|scope]\n  Inspect and manage discovered MCP servers.",
	"friction":     "sir friction [--json]\n  Summarize prompts, blocks, service levels, and scoped-lease suggestions.",
	"audit":        "sir audit\n  One-screen security summary of this session.",
	"log":          "sir log [verify|archive|export]\n  Show, verify, archive, or export the decision ledger.",
	"replay":       "sir replay [--profile strict]\n  Project recorded decisions under another policy profile.",
	"trace":        "sir trace\n  Export this session's ledger as a shareable HTML timeline.",
	"posture":      "sir posture [--json]\n  Show install, policy, MCP, runtime, and ledger posture.",
	"capabilities": "sir capabilities [--json]\n  Show per-agent support and hook coverage.",
	"approvals":    "sir approvals [--json]\n  Show pending asks, retry grants, and everything you've approved.",
	"relay":        "sir relay [--addr :8787] [--dedup 10m] [--digest 1h]\n  Run the central Slack relay (needs SIR_SLACK_WEBHOOK).",
	"demo":         "sir demo\n  Run a 60-second tour of what sir blocks.",
}

// wantsFriction reports whether --friction was passed (e.g. `sir audit --friction`).
func wantsFriction(args []string) bool {
	for _, a := range args {
		if a == "--friction" {
			return true
		}
	}
	return false
}

// filterFlag returns args with the given flag removed.
func filterFlag(args []string, flag string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a != flag {
			out = append(out, a)
		}
	}
	return out
}

// wantsHelp reports whether args request help.
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--help" || a == "-h" {
			return true
		}
	}
	return false
}

// printCommandHelp prints help for a single command. Falls back to a pointer to
// the global help when no detailed entry exists — but never runs the command.
func printCommandHelp(cmd string) {
	if h, ok := commandHelp[cmd]; ok {
		fmt.Println(h)
		return
	}
	fmt.Printf("sir %s — no detailed help yet. Run `sir help` for the full command list.\n", cmd)
}
