package friction

import "strings"

// networkVerb reports whether a verb's target is a host or URL.
func networkVerb(verb string) bool {
	switch verb {
	case "net_external", "net_allowlisted", "net_local", "dns_lookup",
		"push_origin", "push_remote", "mcp_network_unapproved":
		return true
	default:
		return false
	}
}

// hostFromTarget extracts a bare hostname from a network verb's target so
// blocked external hosts can be ranked. It returns "" for non-network verbs.
// Only the host is kept — never the path, query, or userinfo — so nothing
// sensitive in a URL is surfaced in a friction report.
func hostFromTarget(verb, target string) string {
	if !networkVerb(verb) || target == "" {
		return ""
	}
	return hostnameOnly(target)
}

func hostnameOnly(target string) string {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "@"); i >= 0 { // strip user:pass@
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 { // strip :port
		s = s[:i]
	}
	return s
}

// mcpServer extracts the server name from an MCP tool call. Claude-style MCP
// tool names are "mcp__<server>__<tool>"; returns "" for non-MCP entries.
func mcpServer(toolName, verb string) string {
	if !strings.HasPrefix(toolName, "mcp__") {
		if strings.HasPrefix(verb, "mcp_") {
			return "(unknown)"
		}
		return ""
	}
	rest := strings.TrimPrefix(toolName, "mcp__")
	if i := strings.Index(rest, "__"); i >= 0 {
		return rest[:i]
	}
	return rest
}

// displayTarget returns a friction-safe rendering of a target for grouping
// repeated intents: hosts for network verbs, basename-free path elision
// otherwise. It never returns a full filesystem path, to keep the report from
// echoing potentially sensitive locations.
func displayTarget(verb, target string) string {
	if target == "" {
		return "(none)"
	}
	if host := hostFromTarget(verb, target); host != "" {
		return host
	}
	// For non-network verbs, collapse a path to its last element so the
	// report stays informative without echoing directory structure.
	t := strings.TrimRight(target, "/")
	if i := strings.LastIndex(t, "/"); i >= 0 {
		return ".../" + t[i+1:]
	}
	return t
}
