package detect

// Meta is the human-facing description of a detection. The four narrative
// fields answer the questions a curated alert must answer: what happened,
// why it mattered, whether data left the machine, and what to do next.
type Meta struct {
	ID        ID
	Title     string
	What      string
	Why       string
	DataLeft  string // default data-egress statement; the live event may override
	NextStep  string
	BaseRoute Route
	Severity  Severity
}

// catalog is the closed set of detection metadata, keyed by ID. It is the
// single source of truth for enumeration (sir friction), curated Slack
// messages, and the public-contract test.
var catalog = map[ID]Meta{
	SecretToExternalEgress: {
		ID:        SecretToExternalEgress,
		Title:     "Secret context attempted external egress",
		What:      "The agent read secret-labeled data this turn, then tried to send traffic to an external host.",
		Why:       "This is the canonical exfiltration shape: read a credential, then reach out off-box.",
		DataLeft:  "Blocked before the request completed — no data left the machine.",
		NextStep:  "Run `sir explain --last`. If the host is legitimate, add a narrow lease: `sir allow-host <host> --ttl 15m`.",
		BaseRoute: RouteSIEM,
		Severity:  SeverityHigh,
	},
	SecretToPushRemote: {
		ID:        SecretToPushRemote,
		Title:     "Secret context attempted a push to a remote",
		What:      "The agent carried secret-labeled context this turn, then tried to push to a git remote.",
		Why:       "A push under secret taint can leak credentials into commit history or a remote you do not control.",
		DataLeft:  "Blocked before the push completed — nothing was pushed.",
		NextStep:  "Run `sir explain --last`. If the remote is trusted, `sir allow-remote <name>`, or clear taint with `sir unlock` at a turn boundary.",
		BaseRoute: RouteSIEM,
		Severity:  SeverityHigh,
	},
	MCPInjectionThenAction: {
		ID:        MCPInjectionThenAction,
		Title:     "MCP injection followed by an action",
		What:      "An MCP response contained injection markers and the agent then attempted an action under that taint.",
		Why:       "A compromised or malicious MCP server can steer the agent into actions the developer never asked for.",
		DataLeft:  "The action was gated; check the explanation to confirm nothing executed.",
		NextStep:  "Run `sir explain --last`. Revoke or wrap the server: `sir mcp revoke <name>` or route it through `sir mcp-proxy`.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	NewMCPServerUsed: {
		ID:        NewMCPServerUsed,
		Title:     "New MCP server exercised",
		What:      "A freshly discovered or recently approved MCP server was used inside its onboarding window.",
		Why:       "New servers warrant a closer look before they are trusted with quiet, silent allows.",
		DataLeft:  "No exfiltration implied; this is an onboarding-visibility signal.",
		NextStep:  "Review the server with `sir mcp list`. Approve it (`sir mcp approve <name>`) or trust it (`sir trust <name>`).",
		BaseRoute: RouteSIEM,
		Severity:  SeverityMedium,
	},
	MCPBinaryOrConfigDrift: {
		ID:        MCPBinaryOrConfigDrift,
		Title:     "MCP server binary or config drifted",
		What:      "An approved MCP server's binary hash or config no longer matches the recorded baseline.",
		Why:       "Drift can mean a silent swap of the server binary under a previously trusted name.",
		DataLeft:  "No data egress implied; the drift itself is the signal.",
		NextStep:  "Run `sir explain --last`. Re-approve only if the change is expected: `sir mcp approve <name>`.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	AgentPostureTamper: {
		ID:        AgentPostureTamper,
		Title:     "Agent posture file tampered",
		What:      "A hook config, CLAUDE.md, .mcp.json, or sentinel file changed outside sir's managed path.",
		Why:       "Posture tamper is how an attacker disables the guardrails before doing the real thing.",
		DataLeft:  "No data egress implied; the tamper is the signal.",
		NextStep:  "Run `sir doctor` to inspect and restore, then `sir explain --last` for the diff.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	PackageInstallPostureMutation: {
		ID:        PackageInstallPostureMutation,
		Title:     "Package install mutated posture",
		What:      "A package install coincided with a change to a posture/control-plane file.",
		Why:       "Install scripts that rewrite control-plane state are a classic supply-chain foothold.",
		DataLeft:  "No data egress implied; the posture change is the signal.",
		NextStep:  "Run `sir explain --last` and `sir doctor` to review and restore the affected files.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	RepeatedDeniedIntent: {
		ID:        RepeatedDeniedIntent,
		Title:     "Repeated denied intent",
		What:      "The same action was denied or prompted repeatedly in this session.",
		Why:       "Repetition usually means the policy is too tight for this workflow, not an attack.",
		DataLeft:  "Nothing left the machine; this is a friction signal for the developer.",
		NextStep:  "Run `sir friction` to see the noisy rule, then `sir policy suggest` for a safer scoped lease.",
		BaseRoute: RouteLocal,
		Severity:  SeverityLow,
	},
	CredentialInToolOutput: {
		ID:        CredentialInToolOutput,
		Title:     "Credential detected in tool output",
		What:      "A credential pattern was found in tool or MCP output.",
		Why:       "Credentials in output can be captured by the agent and forwarded off-box.",
		DataLeft:  "Detected at the boundary; the value is redacted in the ledger and never exported raw.",
		NextStep:  "Run `sir explain --last` to see the redacted evidence and rotate the exposed credential.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	ControlPlaneIntegrityFailure: {
		ID:        ControlPlaneIntegrityFailure,
		Title:     "Control-plane integrity failure",
		What:      "sir's own control plane is compromised or wedged: deny-all posture, an unrestored hook tamper, or ledger corruption.",
		Why:       "When the guardrails themselves are not trustworthy, every later decision is suspect.",
		DataLeft:  "Unknown — treat as potential compromise until investigated.",
		NextStep:  "Run `sir doctor` to recover. If it cannot, escalate to security and inspect `sir log verify`.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
	MCPChangeThenPrivilegedUse: {
		ID:        MCPChangeThenPrivilegedUse,
		Title:     "MCP trust change followed by privileged use",
		What:      "An approved MCP server's binary or config drifted, and the session then exercised privileged authority (egress, push, delegation, or persistence).",
		Why:       "A silently swapped server that is immediately used is the shape of a supply-chain pivot — far higher signal than drift alone.",
		DataLeft:  "Depends on the action; check the explanation to confirm whether the privileged use completed.",
		NextStep:  "Run `sir explain --last`. Revoke and re-pin the server: `sir mcp revoke <name>` then `sir mcp approve <name>` only if the change is expected.",
		BaseRoute: RouteSlack,
		Severity:  SeverityHigh,
	},
}

// orderedIDs is the stable enumeration order for Catalog and reports.
var orderedIDs = []ID{
	SecretToExternalEgress,
	SecretToPushRemote,
	MCPInjectionThenAction,
	NewMCPServerUsed,
	MCPBinaryOrConfigDrift,
	AgentPostureTamper,
	PackageInstallPostureMutation,
	RepeatedDeniedIntent,
	CredentialInToolOutput,
	ControlPlaneIntegrityFailure,
	MCPChangeThenPrivilegedUse,
}

// AllIDs returns the closed set of detection IDs in stable order.
func AllIDs() []ID {
	out := make([]ID, len(orderedIDs))
	copy(out, orderedIDs)
	return out
}

// Catalog returns the metadata for every detection in stable order.
func Catalog() []Meta {
	out := make([]Meta, 0, len(orderedIDs))
	for _, id := range orderedIDs {
		out = append(out, catalog[id])
	}
	return out
}

// Lookup returns the metadata for a detection ID. ok is false for unknown IDs.
func Lookup(id ID) (Meta, bool) {
	m, ok := catalog[id]
	return m, ok
}

// Valid reports whether id is a known detection identifier.
func Valid(id ID) bool {
	_, ok := catalog[id]
	return ok
}
