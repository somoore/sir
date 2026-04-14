package hooks

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/config"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	mcppkg "github.com/somoore/sir/pkg/mcp"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func evaluateMCPCredentialLeak(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if l.IsTrustedMCPServer(serverName) {
		return nil, false
	}
	found, patternHint := ScanMCPArgsForCredentials(payload.ToolInput)
	if !found {
		return nil, false
	}

	entry := &ledger.Entry{
		ToolName:  payload.ToolName,
		Verb:      string(policy.VerbMcpCredentialLeak),
		Target:    serverName,
		Decision:  "deny",
		Reason:    fmt.Sprintf("credential pattern in MCP args: %s", patternHint),
		Severity:  "HIGH",
		AlertType: "mcp_credential",
	}
	if EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}

	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatDenyMCPCredential(payload.ToolName, serverName, patternHint),
	}, true
}

func evaluateTaintedMCPServer(payload *HookPayload, state *session.State) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !state.IsMCPServerTainted(serverName) || state.IsTaintedMCPServerAcknowledged(serverName) {
		return nil, false
	}
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   FormatAskPostureElevated("mcp_call", payload.ToolName, string(state.Posture), state.MCPInjectionSignals),
	}, true
}

// Approved MCP calls still need a gate when the payload points at a file
// already carrying secret lineage.
func evaluateTaintedMCPInput(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}

	targets := derivedSecretLineageTargets(payload.ToolInput, projectRoot, state)
	if len(targets) == 0 {
		return nil, false
	}
	target := targets[0]
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   fmt.Sprintf("MCP call touching %s requires approval because it carries secret lineage.", target),
	}, true
}

func derivedSecretLineageTargets(input any, projectRoot string, state *session.State) []string {
	seen := make(map[string]struct{})
	var targets []string
	var walk func(any, string)
	walk = func(value any, key string) {
		switch typed := value.(type) {
		case string:
			if typed == "" || !isPathBearingMCPKey(key) {
				return
			}
			if _, ok := seen[typed]; ok {
				return
			}
			for _, label := range state.DerivedLabelsForPath(ResolveTarget(projectRoot, typed)) {
				if label.Sensitivity != "secret" {
					continue
				}
				seen[typed] = struct{}{}
				targets = append(targets, typed)
				return
			}
		case []interface{}:
			for _, item := range typed {
				walk(item, key)
			}
		case map[string]any:
			for childKey, item := range typed {
				walk(item, childKey)
			}
		}
	}
	walk(input, "")
	return targets
}

func isPathBearingMCPKey(key string) bool {
	normalized := normalizeMCPArgKey(key)
	switch {
	case strings.HasSuffix(normalized, "path"), strings.HasSuffix(normalized, "paths"):
		return true
	case normalized == "file", normalized == "files":
		return true
	case normalized == "artifact", normalized == "artifacts":
		return true
	case normalized == "attachment", normalized == "attachments":
		return true
	default:
		return false
	}
}

func normalizeMCPArgKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// evaluateMCPOnboarding fires when an approved MCP server is within its
// onboarding window — a per-session speed bump on calls that would
// otherwise silently allow. The gate ends when EITHER the wall-clock
// window or the per-session call count is crossed.
//
// Scope honesty: this is friction, not containment. A patient attacker
// can burn the counter with 20 harmless calls in seconds, and a 24h wait
// clears the window. The value is surfacing early MCP activity to the
// user when a server is unfamiliar, NOT stopping a malicious MCP. That
// containment story belongs to `sir mcp-proxy`.
//
// Verdict: always Ask. Never Deny.
//
// Gate is skipped when:
//   - tool is not mcp__*
//   - server is not approved
//   - intent.Verb is not VerbExecuteDryRun (something stronger already fires)
//   - approval record is missing or ApprovedAt is zero (grandfathered)
//   - config cannot be loaded (fail open — friction only)
//   - config disables onboarding (both knobs must be positive)
//   - age >= window OR call count >= threshold
func evaluateMCPOnboarding(intent Intent, payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	if intent.Verb != policy.VerbExecuteDryRun {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	record, ok := l.MCPApprovals[serverName]
	if !ok || record.ApprovedAt.IsZero() {
		return nil, false
	}
	cfg, _, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "sir: onboarding: config load error, skipping gate: %v\n", err)
		return nil, false
	}
	if !cfg.OnboardingEnabled() {
		return nil, false
	}

	window := time.Duration(cfg.MCPOnboardingWindowHours) * time.Hour
	age := time.Since(record.ApprovedAt)
	count := state.MCPOnboardingCallCount(serverName)
	if age >= window || count >= cfg.MCPOnboardingCallCount {
		return nil, false
	}

	newCount := state.BumpMCPOnboardingCall(serverName)
	saveSessionBestEffort(state)

	entry := &ledger.Entry{
		ToolName: payload.ToolName,
		Verb:     string(policy.VerbMcpOnboarding),
		Target:   serverName,
		Decision: string(policy.VerdictAsk),
		Reason: fmt.Sprintf(
			"MCP onboarding: server %q within window (age=%s, session call %d/%d)",
			serverName, age.Round(time.Second), newCount, cfg.MCPOnboardingCallCount,
		),
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append (onboarding): %v\n", err)
	}

	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason: fmt.Sprintf(
			"MCP server %q is within its onboarding window. This is call %d of %d in this session; approved %s ago. Approve to continue — friction only, not a security block.",
			serverName, newCount, cfg.MCPOnboardingCallCount, age.Round(time.Second),
		),
	}, true
}

// evaluateMCPBinaryDrift detects that the MCP command binary has changed
// since approval. Fast-path: stat for mtime; if mtime matches the
// recorded value, skip. Otherwise rehash the binary and compare against
// the stored hash. Mismatch → Ask via VerbMcpBinaryDrift.
//
// Only fires when:
//   - tool is mcp__*
//   - server is approved
//   - intent.Verb is VerbExecuteDryRun (silent-allow path) — earlier
//     verbs like VerbMcpNetworkUnapproved or VerbMcpUnapproved already
//     surfaced a more specific concern with its own remediation hint
//     (`sir allow-host <host>`), so drift must not short-circuit them
//   - MCPApprovals[name] carries a non-empty CommandHash
//     (empty hash means "could not pin at approval time" — documented
//      limitation, honest about what we cannot verify)
//
// Scope honesty: this catches local binary substitution post-approval
// (supply-chain replacement, malicious package upgrade). It does not
// catch content-equivalent-but-different binaries (e.g., recompile with
// same output), and it does not apply to npx/uvx/PATH-only servers
// whose binary identity cannot be pinned.
func evaluateMCPBinaryDrift(intent Intent, payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	if intent.Verb != policy.VerbExecuteDryRun {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	record, ok := l.MCPApprovals[serverName]
	if !ok || record.CommandHash == "" || record.Command == "" {
		return nil, false
	}

	// Fast-path: if mtime matches, skip rehash.
	currentModTime, currentHash, err := mcppkg.StatCommand(record.Command)
	if err != nil {
		// Transient stat errors should not break policy evaluation; log
		// and fail-open (friction only).
		fmt.Fprintf(os.Stderr, "sir: binary-drift stat error for %s: %v\n", serverName, err)
		return nil, false
	}

	// If the binary is gone entirely, treat that as drift. A deleted
	// binary that MCP is allegedly still running must be surfaced to
	// the user — something is wrong with their approval.
	if currentHash == "" && record.CommandHash != "" {
		return driftAsk(payload, serverName, record, "binary not found at recorded path", state, projectRoot), true
	}

	if !record.CommandModTime.IsZero() && currentModTime.Equal(record.CommandModTime) && currentHash == record.CommandHash {
		return nil, false
	}
	if currentHash == record.CommandHash {
		// mtime changed but content is the same (touch, chmod, etc.).
		// No drift; do not ask. We deliberately do NOT persist the new
		// mtime here — doing so from a read-mostly evaluation path is
		// not worth the lock contention for a cosmetic refresh.
		return nil, false
	}

	return driftAsk(payload, serverName, record, fmt.Sprintf("hash mismatch (approved=%s, now=%s)",
		shortHash(record.CommandHash), shortHash(currentHash)), state, projectRoot), true
}

// driftAsk builds the Ask response for the binary-drift gate and
// appends a ledger entry capturing the mismatch detail.
func driftAsk(payload *HookPayload, serverName string, record lease.MCPApproval, detail string, state *session.State, projectRoot string) *HookResponse {
	saveSessionBestEffort(state)
	entry := &ledger.Entry{
		ToolName:  payload.ToolName,
		Verb:      string(policy.VerbMcpBinaryDrift),
		Target:    serverName,
		Decision:  string(policy.VerdictAsk),
		Reason:    fmt.Sprintf("binary drift: %s", detail),
		Severity:  "MEDIUM",
		AlertType: "mcp_binary_drift",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append (binary-drift): %v\n", err)
	}
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason: fmt.Sprintf(
			"MCP server %q command binary changed since approval (%s). Approve once to continue, or run `sir mcp revoke %s && sir mcp approve %s` after confirming the new binary is intended. Approved %s; command=%s.",
			serverName, detail, serverName, serverName,
			record.ApprovedAt.Format(time.RFC3339), record.Command,
		),
	}
}

// shortHash returns the first 12 hex chars of a sha256, enough to
// disambiguate in an ask message without overwhelming it.
func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func evaluateElevatedPosture(intent Intent, state *session.State) (*HookResponse, bool) {
	if state.Posture != policy.PostureStateElevated && state.Posture != policy.PostureStateCritical {
		return nil, false
	}
	// Elevated posture stays visible in status/compact output and still gates
	// delegation plus repeated calls back into the tainted MCP server, but it
	// should not degrade ordinary local Bash/Edit traffic into endless prompts.
	_ = intent
	_ = state
	return nil, false
}
