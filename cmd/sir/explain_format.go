package main

import (
	"fmt"
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

// verbMetadata holds the per-verb prose used by the explain renderer. Adding
// a new verb is a single map entry rather than three parallel switch edits
// across verbHumanDescription, sinkClassification, and verbPolicyDescription.
//
// humanTemplate is either a static phrase or a fmt template that receives
// extractHost(target) or filepath.Base(target) — whichever is documented
// next to the entry. An empty sinkClass means the verb does not participate
// in sink classification.
type verbMetadata struct {
	humanStatic   string
	humanHostTmpl string // fmt template, %s = extractHost(target)
	humanBaseTmpl string // fmt template, %s = filepath.Base(target)
	sinkClass     string
	policy        string
}

var verbMetadataTable = map[string]verbMetadata{
	"net_external": {
		humanHostTmpl: "network request to %s",
		sinkClass:     "untrusted (external host not in approved_hosts)",
		policy:        "Secret-labeled session data cannot flow to untrusted external hosts",
	},
	"net_allowlisted": {
		humanHostTmpl: "network request to approved host %s",
		sinkClass:     "approved (host in lease approved_hosts)",
		policy:        "Network requests to approved hosts require developer confirmation",
	},
	"net_local": {
		humanStatic: "network request to localhost",
		sinkClass:   "trusted (loopback address)",
		policy:      "Loopback network requests are always allowed",
	},
	"push_origin": {
		humanStatic: "git push to origin",
		sinkClass:   "approved (remote in approved_remotes)",
		policy:      "Git push to approved remotes requires confirmation when session has secrets",
	},
	"push_remote": {
		humanStatic: "git push to unapproved remote",
		sinkClass:   "untrusted (remote not in approved_remotes)",
		policy:      "Git push to unapproved remotes is always blocked when session has secrets",
	},
	"run_ephemeral": {
		humanStatic: "ephemeral code execution (npx)",
		policy:      "Ephemeral remote code execution (npx) always requires approval",
	},
	"read_ref": {
		humanBaseTmpl: "file read: %s",
		policy:        "Reading sensitive files requires developer approval; labels session as secret",
	},
	"stage_write": {
		humanBaseTmpl: "file write: %s",
		policy:        "Writing posture files always requires approval",
	},
	"execute_dry_run": {
		humanStatic: "shell command",
		policy:      "Standard shell commands are silently allowed",
	},
	"run_tests": {
		humanStatic: "test execution",
		policy:      "Test execution is silently allowed",
	},
	"commit": {
		humanStatic: "git commit",
		policy:      "Git commits are silently allowed",
	},
	"list_files": {
		humanStatic: "file listing",
		policy:      "File listing is silently allowed",
	},
	"search_code": {
		humanStatic: "code search",
		policy:      "Code search is silently allowed",
	},
	"env_read": {
		humanStatic: "environment variable access",
		policy:      "Environment variable access may expose secrets; always requires approval",
	},
	"dns_lookup": {
		humanStatic: "DNS lookup (potential data exfiltration channel)",
		sinkClass:   "untrusted (DNS can exfiltrate data)",
		policy:      "DNS lookups are blocked (potential data exfiltration via DNS)",
	},
	"persistence": {
		humanStatic: "persistence mechanism (crontab/launchctl)",
		policy:      "Persistence mechanisms (cron, launchctl) always require approval",
	},
	"sudo": {
		humanStatic: "elevated privilege command",
		policy:      "Elevated privilege commands always require approval",
	},
	"delete_posture": {
		humanStatic: "delete/link targeting posture file",
		policy:      "Deleting or linking posture files always requires approval",
	},
	"sir_self": {
		humanStatic: "sir configuration command",
		policy:      "Modifying sir configuration always requires developer approval",
	},
	"mcp_unapproved": {
		humanStatic: "unapproved MCP server tool call",
		policy:      "Unapproved MCP server tools always require approval",
	},
	"mcp_credential_leak": {
		humanStatic: "MCP tool call with credential pattern in arguments",
		policy:      "Credential patterns in MCP tool arguments are unconditionally blocked. The escape hatch is `sir trust <server>` for MCP servers designed to receive opaque tokens (rare).",
	},
	"mcp_injection_detected": {
		humanStatic: "MCP response containing injection patterns",
		policy:      "Suspicious instructions in an MCP response raise session posture; the next tool call is gated",
	},
	"credential_detected": {
		humanStatic: "structured credentials in tool output",
		policy:      "Structured credentials in tool output escalate the IFC label to secret (no block)",
	},
	"delegate": {
		humanStatic: "sub-agent delegation (Agent tool / SubagentStart)",
		policy:      "Sub-agent delegation is denied in a secret session and follows the lease policy otherwise",
	},
	"elicitation_harvest": {
		humanStatic: "elicitation prompt with credential-harvest pattern",
		policy:      "Elicitation prompts matching credential-harvest patterns are warned but not blocked",
	},
}

// verbHumanDescription returns a plain-English description of what the
// verb+target represents.
func verbHumanDescription(verb, target string) string {
	meta, ok := verbMetadataTable[verb]
	if !ok {
		return verb
	}
	switch {
	case meta.humanHostTmpl != "":
		return fmt.Sprintf(meta.humanHostTmpl, extractHost(target))
	case meta.humanBaseTmpl != "":
		return fmt.Sprintf(meta.humanBaseTmpl, filepath.Base(target))
	default:
		return meta.humanStatic
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
// Sourced from verbMetadataTable; verbs without a sinkClass return "".
func sinkClassification(verb string) string {
	return verbMetadataTable[verb].sinkClass
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

// verbPolicyDescription returns the enforcement rule for a verb. Sourced from
// verbMetadataTable; unknown verbs return a clear fallback string.
func verbPolicyDescription(verb string) string {
	if meta, ok := verbMetadataTable[verb]; ok && meta.policy != "" {
		return meta.policy
	}
	return "Unknown policy rule for verb: " + verb
}
