package hooks

import (
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// HookPayload is sir's normalized internal hook payload. It is a type alias
// for agent.HookPayload so the hooks package stays agent-agnostic while
// existing tests (and tests/bypass_test.go) continue to work unchanged.
type HookPayload = agent.HookPayload

// HookResponse is sir's internal verdict carrier inside the hooks package.
// It is NOT the wire-format response — adapters own that (see
// agent.ClaudeAgent.FormatPreToolUseResponse). Kept here so test code and
// handlers can pass decisions around as a single value.
type HookResponse struct {
	Decision policy.Verdict
	Reason   string
}

// Evaluate is the PreToolUse hook handler.
// It reads a hook payload from stdin, classifies the intent,
// evaluates it against the policy, logs to the ledger, and writes the response to stdout.
//
// ag is the host-agent adapter used to parse the incoming payload and format
// the outgoing response. Supported adapters: Claude Code, Codex.
func Evaluate(projectRoot string, ag agent.Agent) error {
	// Read stdin
	payload, err := readPayload(os.Stdin, ag)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	// Load lease
	l, err := loadLease(projectRoot)
	if err != nil {
		return fmt.Errorf("load lease: %w", err)
	}

	// Load or create session under file lock.
	// The lock covers the entire Load→Evaluate(mutate)→Save pipeline so
	// concurrent PreToolUse/PostToolUse hooks cannot corrupt session state.
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		state, sErr := loadOrCreateSession(projectRoot, l)
		if sErr != nil {
			return fmt.Errorf("load session: %w", sErr)
		}
		var eErr error
		resp, eErr = evaluatePayload(payload, l, state, projectRoot, ag)
		return eErr
	})
	if lockErr != nil {
		return fmt.Errorf("evaluate: %w", lockErr)
	}

	// Write response to stdout via the agent adapter
	return writeResponse(os.Stdout, resp, ag)
}

// evaluatePayload is the testable core of the PreToolUse handler.
//
// The optional trailing ag argument is used for OTLP telemetry attribution
// (sir.agent.id / sir.agent.name resource attributes). Variadic rather than
// a required parameter so the dozens of existing test callers don't need
// to be touched; when omitted, agent attribution is simply absent from the
// telemetry payload.
func evaluatePayload(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string, agOpt ...agent.Agent) (*HookResponse, error) {
	var ag agent.Agent
	if len(agOpt) > 0 {
		ag = agOpt[0]
	}
	// Verify session integrity BEFORE any mutations — detect external tampering
	// (e.g., agent running `python3 -c` or `sed` to clear deny_all or secret_session).
	// Must run before MaybeAdvanceTurn which mutates state.
	if !session.VerifySessionIntegrity(state) {
		state.SetDenyAll("session.json modified outside sir")
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   FormatSessionIntegrityFatal(),
		}, nil
	}

	// Detect turn boundaries using time gap heuristic.
	// Tool calls within a single Claude response fire in rapid succession.
	// A gap longer than TurnGapThreshold signals a new user message (new turn).
	// When the turn advances, turn-scoped secret approvals are cleared.
	state.MaybeAdvanceTurn(time.Now())

	// Check for session-fatal deny-all
	if state.DenyAll {
		reason := FormatDenyAll(state.DenyAllReason)
		return &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   reason,
		}, nil
	}

	// Capture pending injection alert but do NOT return early.
	// The alert will be overlaid on the final verdict after mister-core evaluation.
	// Returning early here would short-circuit a DENY from mister-core into an ASK,
	// allowing an attacker to exfiltrate via a carelessly approved prompt.
	var pendingInjectionDetail string
	if state.PendingInjectionAlert {
		pendingInjectionDetail = state.InjectionAlertDetail
		state.ClearPendingInjectionAlert()
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
	}

	// Verify lease integrity on every PreToolUse — detects external tampering
	// of lease.json by an attacker trying to whitelist hosts or relax policy.
	if !VerifyLeaseIntegrity(projectRoot, state) {
		state.SetDenyAll("lease.json modified outside approved write")
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   FormatLeaseIntegrityFatal(),
		}, nil
	}

	// Map tool call to intent
	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)

	// Agent delegation during secret session is handled by mister-core
	// (policy.rs returns deny for delegate verb when secret_session is true).
	// Do NOT intercept here with a softer verdict — the Go layer must never be
	// more permissive than Rust. CLAUDE.md invariant: "Sub-agents inherit
	// parent's secret_session flag — secrets cannot be laundered through
	// delegation." A parity test in parity_test.go locks this in.

	// Credential argument scanning for MCP tools.
	// Scans ALL untrusted MCP tool arguments for credential patterns,
	// regardless of session state. A developer typing "sk_live_..." into a
	// prompt (without having read a credential file) must still be caught.
	//
	// Verdict is DENY, not ask. The documented policy in
	// docs/contributor/security-engineering-core.md::Enforcement Gradient and
	// ARCHITECTURE.md both say block.
	// Credential disclosure to an untrusted MCP server is an
	// unambiguous denial — the escape hatch is `sir trust <server>`, not
	// a per-call approval prompt.
	//
	// TrustedMCPServers are exempt at the lease level. If a server
	// legitimately needs to receive opaque tokens (e.g., a secrets-vault
	// MCP), add it with `sir trust <server>`.
	if resp, handled := evaluateMCPCredentialLeak(payload, l, state, projectRoot); handled {
		return resp, nil
	}

	// Block MCP calls to tainted servers after injection detection.
	// If a server has returned injection signals and the session posture is critical,
	// require approval for subsequent calls to that server.
	if resp, handled := evaluateTaintedMCPServer(payload, state); handled {
		return resp, nil
	}

	// Posture enforcement: when session posture is elevated or critical
	// (e.g., after MCP injection detection), require approval for operations that
	// would normally be silent-allow. Without this, an elevated posture only gates
	// the specific tainted MCP server, not the broader attack surface.
	if resp, handled := evaluateElevatedPosture(intent, state); handled {
		return resp, nil
	}

	// Assign IFC labels
	var labels core.Label
	if intent.Verb == policy.VerbReadRef || intent.Verb == policy.VerbStageWrite {
		labels = LabelsForTarget(intent.Target, l, projectRoot)
	} else if payload.ToolName == "Agent" {
		labels = LabelsForAgent()
	} else if isToolMCP(payload.ToolName) {
		labels = LabelsForMCPTool()
	} else {
		labels = core.Label{
			Sensitivity: "public",
			Trust:       "trusted",
			Provenance:  "user",
		}
	}

	// If this is an install command, snapshot sentinel files
	if intent.IsInstall {
		sentinelHashes := HashSentinelFiles(projectRoot, l.SentinelFilesForInstall)
		lockfiles := LockfileForManager(intent.Manager)
		var lockfileHash string
		if len(lockfiles) > 0 {
			lhashes := HashSentinelFiles(projectRoot, lockfiles)
			for _, h := range lhashes {
				if h != "" {
					lockfileHash = h
					break
				}
			}
		}
		state.SetPendingInstall(intent.Target, intent.Manager, sentinelHashes, lockfileHash)

		// Check if package is declared in the lockfile
		pkgName := extractPackageName(intent.Target, intent.Manager)
		if pkgName != "" && !isPackageInLockfile(projectRoot, intent.Manager, pkgName) {
			if err := state.Save(); err != nil {
				fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
			}
			return &HookResponse{
				Decision: policy.VerdictAsk,
				Reason:   FormatAskInstall(pkgName, intent.Manager),
			}, nil
		}
	}

	// Build core request
	req := buildCoreRequest(projectRoot, payload, intent, l, state, labels)

	// Warn if mister-core binary is not available — enforcement is degraded.
	if _, lookErr := exec.LookPath(core.CoreBinaryPath); lookErr != nil {
		fmt.Fprintf(os.Stderr, "sir WARNING: mister-core binary not found — using Go fallback. Policy enforcement is degraded. Reinstall sir to restore full protection.\n")
	}

	// Call mister-core (or fallback)
	coreResp, err := core.Evaluate(req)
	if err != nil {
		return nil, fmt.Errorf("core evaluate: %w", err)
	}

	// Build hook response with human-readable messages
	hookResp := &HookResponse{
		Decision: coreResp.Decision,
		Reason:   coreResp.Reason,
	}

	// Update session state based on verdict
	if coreResp.Decision == policy.VerdictAllow || coreResp.Decision == policy.VerdictAsk {
		if intent.IsSensitive && intent.Verb == policy.VerbReadRef {
			// If a sensitive read is allowed/asked, mark session as secret.
			// Default to "turn" scope: the secret flag clears automatically when the
			// next user turn begins (detected via time gap between tool calls).
			if coreResp.Decision == policy.VerdictAllow {
				state.MarkSecretSession()
			}
			// Include scope explanation in ask response for sensitive reads
			if coreResp.Decision == policy.VerdictAsk {
				hookResp.Reason = FormatAskSensitive(intent.Target, string(state.ApprovalScope))
				fmt.Fprintf(os.Stderr, "\n  Note: approving this will block external network requests\n")
				fmt.Fprintf(os.Stderr, "  until the agent finishes responding (turn-scoped by default).\n")
				fmt.Fprintf(os.Stderr, "  To clear now: sir unlock\n\n")
			}
		}
		if labels.Trust == "verified_origin" || labels.Provenance == "external_package" {
			state.MarkUntrustedRead()
		}
	}

	// Format the deny reason as a human-readable block message with WHAT/WHY/HOW.
	// The raw mister-core reason is too terse for developer-facing output.
	if coreResp.Decision == policy.VerdictDeny {
		hookResp.Reason = formatDenyReason(coreResp.Reason, intent, state, ag)
	}

	// Overlay pending injection alert on the final verdict.
	// DENY stays DENY (never downgrade). ALLOW upgrades to ASK. ASK stays ASK.
	// This ensures mister-core's hard denials are never short-circuited.
	if pendingInjectionDetail != "" {
		injectionWarning := fmt.Sprintf("sir WARNING: A previous tool response contained suspicious patterns. %s", pendingInjectionDetail)
		switch hookResp.Decision {
		case policy.VerdictDeny:
			// Keep deny — append warning to reason so developer understands both threats
			hookResp.Reason = hookResp.Reason + "\n\n  Additionally: " + injectionWarning
		case policy.VerdictAllow:
			// Upgrade allow → ask
			hookResp.Decision = policy.VerdictAsk
			hookResp.Reason = injectionWarning + "\n\n  This action would normally be allowed, but requires approval due to the suspicious activity."
		case policy.VerdictAsk:
			// Prepend warning to existing ask reason
			hookResp.Reason = injectionWarning + "\n\n  " + hookResp.Reason
		}
	}

	// Save session state
	if err := state.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	// Log to ledger (never log secret content)
	appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, coreResp.Decision, coreResp.Reason, state, ag)

	return hookResp, nil
}
