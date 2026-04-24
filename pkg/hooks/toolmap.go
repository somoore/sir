package hooks

import (
	"strings"

	"github.com/somoore/sir/pkg/config"
	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
)

// Intent describes the classified intent of a tool call.
type Intent struct {
	Verb        policy.Verb
	Target      string
	IsPosture   bool
	IsSensitive bool
	IsInstall   bool
	Manager     string // package manager if IsInstall

	// RemoteName is the extracted git remote name for push_remote /
	// push_origin verbs. Empty for all other verbs. Used by the deny
	// message formatter so "sir allow-remote <name>" gets a real
	// remote name instead of the raw command string (which for a
	// compound like `git push 2>&1 | tail -5` would leak shell
	// metacharacters into the fix suggestion).
	RemoteName string
}

// MapToolToIntent maps a Claude Code tool call to a sir intent.
func MapToolToIntent(toolName string, toolInput map[string]interface{}, l *lease.Lease) Intent {
	switch {
	case toolName == "Read":
		return mapRead(toolInput, l)
	case toolName == "Write" || toolName == "Edit":
		return mapWrite(toolInput, l)
	case toolName == "Bash":
		return mapBash(toolInput, l)
	case toolName == "Agent":
		return mapAgent(toolInput, l)
	case toolName == "WebFetch":
		return mapWebFetch(toolInput, l)
	case toolName == "WebSearch":
		return mapWebSearch(toolInput, l)
	case strings.HasPrefix(toolName, "mcp__"):
		return mapMCP(toolName, toolInput, l)
	case toolName == "Grep":
		return mapGrep(toolInput, l)
	case toolName == "Glob":
		return Intent{Verb: policy.VerbListFiles, Target: extractTarget(toolInput)}
	default:
		return Intent{Verb: policy.VerbExecuteDryRun, Target: toolName}
	}
}

func mapRead(toolInput map[string]interface{}, l *lease.Lease) Intent {
	target := extractFilePath(toolInput)
	return Intent{
		Verb:        policy.VerbReadRef,
		Target:      target,
		IsPosture:   IsPostureFileResolved(target, l),
		IsSensitive: IsSensitivePathResolved(target, l),
	}
}

func mapWrite(toolInput map[string]interface{}, l *lease.Lease) Intent {
	target := extractFilePath(toolInput)
	if target == "" {
		targets := extractApplyPatchTargets(extractPatchPayload(toolInput))
		if len(targets) > 0 {
			target = strings.Join(targets, ", ")
			for _, candidate := range targets {
				if IsPostureFileResolved(candidate, l) {
					return Intent{
						Verb:      policy.VerbStageWrite,
						Target:    target,
						IsPosture: true,
					}
				}
			}
		}
	}
	return Intent{
		Verb:      policy.VerbStageWrite,
		Target:    target,
		IsPosture: IsPostureFileResolved(target, l),
	}
}

func mapBash(toolInput map[string]interface{}, l *lease.Lease) Intent {
	cmd := extractCommand(toolInput)
	return mapShellCommand(cmd, l)
}

func mapGrep(toolInput map[string]interface{}, l *lease.Lease) Intent {
	// Grep's path can be a specific sensitive file — treat that as a sensitive read.
	path, _ := toolInput["path"].(string)
	if path != "" && IsSensitivePathResolved(path, l) {
		return Intent{
			Verb:        policy.VerbReadRef,
			Target:      path,
			IsSensitive: true,
		}
	}
	return Intent{Verb: policy.VerbListFiles, Target: path}
}

func mapAgent(toolInput map[string]interface{}, l *lease.Lease) Intent {
	return Intent{
		Verb:   policy.VerbDelegate,
		Target: extractTarget(toolInput),
	}
}

func mapWebFetch(toolInput map[string]interface{}, l *lease.Lease) Intent {
	urlStr, _ := toolInput["url"].(string)
	dest := ClassifyNetworkDest(urlStr, l)
	verb := policy.VerbNetExternal
	switch dest {
	case "loopback":
		verb = policy.VerbNetLocal
	case "approved":
		verb = policy.VerbNetAllowlisted
	}
	return Intent{
		Verb:   verb,
		Target: urlStr,
	}
}

func mapWebSearch(toolInput map[string]interface{}, l *lease.Lease) Intent {
	query, _ := toolInput["query"].(string)
	// WebSearch is external network egress — same policy as net_external.
	// Blocked during secret sessions to prevent query-embedded secret exfiltration.
	return Intent{
		Verb:   policy.VerbNetExternal,
		Target: query,
	}
}

func mapMCP(toolName string, toolInput map[string]interface{}, l *lease.Lease) Intent {
	serverName := extractMCPServerName(toolName)
	if !isApprovedMCPServer(serverName, l) {
		return Intent{
			Verb:   policy.VerbMcpUnapproved,
			Target: toolName,
		}
	}
	if offender := firstUnapprovedURL(toolInput, l); offender != "" {
		return Intent{
			Verb:   policy.VerbMcpNetworkUnapproved,
			Target: ledger.RedactURL(offender),
		}
	}
	if deepVerbGatingEnabled() {
		if intent, ok := deepVerbGateMCPArgs(toolInput, l); ok {
			return intent
		}
	}
	return Intent{
		Verb:   policy.VerbExecuteDryRun,
		Target: toolName,
	}
}

// deepVerbGateMCPArgs is the #5 gate: re-classify MCP tool args into
// native verbs when conventional field names reveal dangerous operations.
// Opt-in via `mcp_deep_verb_gating` config. Returns ok=true only when a
// remapped verb is strictly more cautious than VerbExecuteDryRun — we
// never DOWNGRADE the verb here.
//
// Known limitation: field-rename evasion (base64 payloads, non-English
// keys, server-constructed commands) is out of scope. Document in the
// contributor guide alongside the honest-MCP framing.
func deepVerbGateMCPArgs(toolInput map[string]interface{}, l *lease.Lease) (Intent, bool) {
	if cmd := hookclassify.FirstShellLikeValue(toolInput); cmd != "" {
		intent := mapShellCommand(cmd, l)
		if isRiskyShellVerb(intent.Verb) {
			return intent, true
		}
	}
	if path := hookclassify.FirstWriteLikePath(toolInput); path != "" {
		isPosture := IsPostureFileResolved(path, l)
		isSensitive := IsSensitivePathResolved(path, l)
		if isPosture || isSensitive {
			return Intent{
				Verb:        policy.VerbStageWrite,
				Target:      path,
				IsPosture:   isPosture,
				IsSensitive: isSensitive,
			}, true
		}
	}
	return Intent{}, false
}

// isRiskyShellVerb reports whether a shell-classifier verb warrants
// diverting the MCP call off the silent-allow path. A benign shell
// command (e.g., `ls`) would come back as VerbExecuteDryRun — that is
// the same as what the MCP call would get anyway, so no divert.
func isRiskyShellVerb(v policy.Verb) bool {
	switch v {
	case policy.VerbNetExternal,
		policy.VerbNetAllowlisted,
		policy.VerbDnsLookup,
		policy.VerbSudo,
		policy.VerbPersistence,
		policy.VerbRunEphemeral,
		policy.VerbEnvRead,
		policy.VerbPushRemote,
		policy.VerbPushOrigin,
		policy.VerbDeletePosture:
		return true
	}
	return false
}

// deepVerbGatingEnabled reads ~/.sir/config.json and reports whether the
// deep verb gating flag is set. Fail-open on any config error — this is
// a friction gate, not a security boundary.
func deepVerbGatingEnabled() bool {
	cfg, _, err := config.Load()
	if err != nil {
		return false
	}
	return cfg.MCPDeepVerbGating
}

// firstUnapprovedURL returns the first URL in toolInput whose host is not
// loopback and not in lease.ApprovedHosts. Returns "" if all URLs are
// approved/loopback or no URLs are present.
//
// Known limitation: only catches URLs Claude passes literally. Field-split
// URLs, encoded URLs, and URLs constructed server-side are not detected.
// Containment for malicious MCPs is the OS sandbox in sir mcp-proxy.
func firstUnapprovedURL(toolInput map[string]interface{}, l *lease.Lease) string {
	for _, u := range hookclassify.ExtractMCPURLs(toolInput) {
		if ClassifyNetworkDest(u, l) == "external" {
			return u
		}
	}
	return ""
}

// extractMCPServerName parses the server name from an MCP tool name.
// mcp__servername__toolname → servername
func extractMCPServerName(toolName string) string {
	parts := strings.SplitN(toolName, "__", 3)
	if len(parts) >= 2 {
		return parts[1]
	}
	return toolName
}

// isApprovedMCPServer checks if a server name is in the lease's approved MCP servers list.
func isApprovedMCPServer(serverName string, l *lease.Lease) bool {
	for _, approved := range l.ApprovedMCPServers {
		if approved == serverName {
			return true
		}
	}
	return false
}
