package main

import (
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
)

// decisionTitle returns a human-readable title for the decision.
func decisionTitle(e ledger.Entry) string {
	switch e.Decision {
	case "deny":
		return "Blocked " + verbHumanDescription(e.Verb, e.Target)
	case "ask":
		return "Requires approval: " + verbHumanDescription(e.Verb, e.Target)
	case "allow":
		return "Allowed " + verbHumanDescription(e.Verb, e.Target)
	default:
		return e.Decision + " " + verbHumanDescription(e.Verb, e.Target)
	}
}

// verbHumanDescription returns a plain-English description of what the verb+target represents.
func verbHumanDescription(verb, target string) string {
	switch verb {
	case "net_external":
		return "network request to " + extractHost(target)
	case "net_allowlisted":
		return "network request to approved host " + extractHost(target)
	case "net_local":
		return "network request to localhost"
	case "push_origin":
		return "git push to origin"
	case "push_remote":
		return "git push to unapproved remote"
	case "run_ephemeral":
		return "ephemeral code execution (npx)"
	case "read_ref":
		return "file read: " + filepath.Base(target)
	case "stage_write":
		return "file write: " + filepath.Base(target)
	case "execute_dry_run":
		return "shell command"
	case "run_tests":
		return "test execution"
	case "commit":
		return "git commit"
	case "list_files":
		return "file listing"
	case "search_code":
		return "code search"
	case "env_read":
		return "environment variable access"
	case "dns_lookup":
		return "DNS lookup (potential data exfiltration channel)"
	case "persistence":
		return "persistence mechanism (crontab/launchctl)"
	case "sudo":
		return "elevated privilege command"
	case "delete_posture":
		return "delete/link targeting posture file"
	case "sir_self":
		return "sir configuration command"
	case "mcp_unapproved":
		return "unapproved MCP server tool call"
	case "mcp_credential_leak":
		return "MCP tool call with credential pattern in arguments"
	case "mcp_injection_detected":
		return "MCP response containing injection patterns"
	case "credential_detected":
		return "structured credentials in tool output"
	case "delegate":
		return "sub-agent delegation (Agent tool / SubagentStart)"
	case "elicitation_harvest":
		return "elicitation prompt with credential-harvest pattern"
	default:
		return verb
	}
}

// extractHost extracts a hostname from a URL or target string.
func extractHost(target string) string {
	t := target
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(t, prefix) {
			t = t[len(prefix):]
			break
		}
	}
	if idx := strings.Index(t, "/"); idx >= 0 {
		t = t[:idx]
	}
	if idx := strings.LastIndex(t, ":"); idx >= 0 {
		t = t[:idx]
	}
	if t == "" {
		return target
	}
	return t
}

// sinkClassification returns the sink trust level for network/push verbs.
func sinkClassification(verb string) string {
	switch verb {
	case "net_external":
		return "untrusted (external host not in approved_hosts)"
	case "net_allowlisted":
		return "approved (host in lease approved_hosts)"
	case "net_local":
		return "trusted (loopback address)"
	case "push_remote":
		return "untrusted (remote not in approved_remotes)"
	case "push_origin":
		return "approved (remote in approved_remotes)"
	case "dns_lookup":
		return "untrusted (DNS can exfiltrate data)"
	default:
		return ""
	}
}

func explainEvidencePreview(evidence string) string {
	if len(evidence) <= 512 {
		return evidence
	}
	return evidence[:509] + "..."
}

func indentExplainBlock(s, prefix string) string {
	if s == "" {
		return prefix
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

// verbPolicyDescription returns the enforcement rule for a verb.
func verbPolicyDescription(verb string) string {
	switch verb {
	case "net_external":
		return "Secret-labeled session data cannot flow to untrusted external hosts"
	case "net_allowlisted":
		return "Network requests to approved hosts require developer confirmation"
	case "net_local":
		return "Loopback network requests are always allowed"
	case "push_origin":
		return "Git push to approved remotes requires confirmation when session has secrets"
	case "push_remote":
		return "Git push to unapproved remotes is always blocked when session has secrets"
	case "run_ephemeral":
		return "Ephemeral remote code execution (npx) always requires approval"
	case "read_ref":
		return "Reading sensitive files requires developer approval; labels session as secret"
	case "stage_write":
		return "Writing posture files always requires approval"
	case "execute_dry_run":
		return "Standard shell commands are silently allowed"
	case "run_tests":
		return "Test execution is silently allowed"
	case "commit":
		return "Git commits are silently allowed"
	case "list_files":
		return "File listing is silently allowed"
	case "search_code":
		return "Code search is silently allowed"
	case "env_read":
		return "Environment variable access may expose secrets; always requires approval"
	case "dns_lookup":
		return "DNS lookups are blocked (potential data exfiltration via DNS)"
	case "persistence":
		return "Persistence mechanisms (cron, launchctl) always require approval"
	case "sudo":
		return "Elevated privilege commands always require approval"
	case "delete_posture":
		return "Deleting or linking posture files always requires approval"
	case "sir_self":
		return "Modifying sir configuration always requires developer approval"
	case "mcp_unapproved":
		return "Unapproved MCP server tools always require approval"
	case "mcp_credential_leak":
		return "Credential patterns in MCP tool arguments are unconditionally blocked. The escape hatch is `sir trust <server>` for MCP servers designed to receive opaque tokens (rare)."
	case "mcp_injection_detected":
		return "Suspicious instructions in an MCP response raise session posture; the next tool call is gated"
	case "credential_detected":
		return "Structured credentials in tool output escalate the IFC label to secret (no block)"
	case "delegate":
		return "Sub-agent delegation is denied in a secret session and follows the lease policy otherwise"
	case "elicitation_harvest":
		return "Elicitation prompts matching credential-harvest patterns are warned but not blocked"
	default:
		return "Unknown policy rule for verb: " + verb
	}
}
