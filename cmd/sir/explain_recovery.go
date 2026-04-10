package main

import (
	"fmt"

	"github.com/somoore/sir/pkg/ledger"
)

// recoveryOptions returns suggested recovery actions based on the decision.
func recoveryOptions(e ledger.Entry) []string {
	if e.Decision == "allow" {
		return nil
	}

	var opts []string

	switch e.Verb {
	case "net_external":
		host := extractHost(e.Target)
		opts = append(opts, fmt.Sprintf("sir allow-host %-20s — Permanently allow this host (do this once, sticks forever)", host))
		opts = append(opts, "sir unlock                       — Lift the secret-session lock (only if a secret read locked you)")

	case "push_remote":
		opts = append(opts, "sir allow-remote <name>          — Permanently allow this remote")
		opts = append(opts, "sir unlock                       — Lift the secret-session lock (only if a secret read locked you)")

	case "push_origin":
		opts = append(opts, "sir unlock                       — Lift the secret-session lock, then retry")

	case "dns_lookup":
		opts = append(opts, "DNS lookups are unconditionally blocked — they can encode data in hostnames.")
		opts = append(opts, "Use curl or wget to an approved host instead. There is no `unlock` for DNS.")

	case "read_ref":
		if e.Decision == "ask" {
			opts = append(opts, "Approve the read when prompted   — Session will be marked as carrying secrets")
			opts = append(opts, "Deny the read                    — Session stays clean, no egress restrictions")
		}

	case "stage_write":
		if e.Decision == "ask" {
			opts = append(opts, "Approve the write when prompted  — Posture file writes always require approval")
			opts = append(opts, "Deny the write                   — Posture file stays unchanged")
		}

	case "env_read":
		opts = append(opts, "Approve the read when prompted   — Session will be marked as carrying secrets")
		opts = append(opts, "Deny the read                    — Session stays clean")

	case "run_ephemeral":
		opts = append(opts, "Approve when prompted            — npx always requires approval (runs remote code)")

	case "persistence":
		opts = append(opts, "Approve when prompted            — Persistence mechanisms always require approval")
		opts = append(opts, "Deny to prevent scheduled tasks   — Prevents exfiltration that outlives the session")

	case "sudo":
		opts = append(opts, "Approve when prompted            — Elevated commands always require approval")

	case "delete_posture":
		opts = append(opts, "Approve when prompted            — Posture file deletion always requires approval")

	case "sir_self":
		opts = append(opts, "Approve when prompted            — sir configuration changes require approval")

	case "mcp_unapproved":
		opts = append(opts, "sir install                      — Re-run install to auto-discover MCP servers")
		opts = append(opts, "Approve when prompted            — Approves this one call only")

	case "mcp_credential_leak":
		opts = append(opts, fmt.Sprintf("sir trust %-20s — Exempt this MCP server from credential scanning", e.Target))
		opts = append(opts, "                                   (rare — only for servers designed to receive tokens)")

	case "delegate":
		opts = append(opts, "sir unlock                       — Lift the secret-session lock, then retry delegation")

	default:
		if e.Decision == "deny" {
			opts = append(opts, "sir doctor                       — Diagnose the block")
			opts = append(opts, "sir why                          — Re-read the decision rationale")
		}
	}

	if e.AlertType == "posture_tamper" || e.AlertType == "sentinel_mutation" {
		opts = nil
		opts = append(opts, "sir doctor                       — Verify and repair posture file integrity")
		opts = append(opts, "sir install                      — Re-install sir hooks from scratch")
		opts = append(opts, "Start a fresh agent session      — Required after session-fatal events (state is irrecoverable)")
	}

	return opts
}
