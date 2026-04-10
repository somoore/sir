package hooks

import (
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// PostHookPayload is sir's normalized PostToolUse payload. Type alias to
// agent.HookPayload so the hooks package stays agent-agnostic while existing
// tests continue to work.
type PostHookPayload = agent.HookPayload

// PostEvaluate is the PostToolUse hook handler.
// It checks for sentinel file mutations after installs,
// posture file tampering via Bash, and updates session state.
//
// ag is the host-agent adapter that owns BOTH parse (stdin) and format
// (stdout). Each adapter decides its own PostToolUse wire contract:
//
//   - Claude Code: returns nil bytes from FormatPostToolUseResponse — the
//     PostToolUse hook doesn't honor permissionDecision, so sir writes
//     non-allow reasons to stderr instead.
//   - Codex: returns a real {"decision":"block","reason":...,
//     "hookSpecificOutput":{...}} JSON body because Codex DOES process
//     PostToolUse responses.
//
// The handler always writes reasons to stderr as a human-visible fallback;
// this is additive, not mutually exclusive, with the adapter's stdout.
func PostEvaluate(projectRoot string, ag agent.Agent) error {
	// Read stdin with size limit
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	payload, err := ag.ParsePostToolUse(data)
	if err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Load lease
	l, err := loadLease(projectRoot)
	if err != nil {
		return fmt.Errorf("load lease: %w", err)
	}

	// Load session and evaluate under file lock.
	// The lock covers Load→PostEvaluate(mutate)→Save so concurrent hooks
	// cannot corrupt session state.
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		state, err := loadOptionalLifecycleSession(projectRoot, "post-evaluate")
		if err != nil {
			return err
		}
		if state == nil {
			// No session — nothing to check.
			return nil
		}
		var pErr error
		resp, pErr = postEvaluatePayload(payload, l, state, projectRoot, ag)
		if pErr != nil {
			return pErr
		}
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return nil
	})
	if lockErr != nil {
		return fmt.Errorf("post-evaluate: %w", lockErr)
	}

	// Write the adapter-owned response to stdout (Codex uses this; Claude
	// returns nil and falls through to stderr). Human-visible reason also
	// goes to stderr regardless, so the developer sees alerts inline.
	if resp != nil && resp.Decision != policy.VerdictAllow {
		if respBytes, fmtErr := ag.FormatPostToolUseResponse(string(resp.Decision), resp.Reason); fmtErr == nil && len(respBytes) > 0 {
			os.Stdout.Write(respBytes) //nolint:errcheck
		}
		fmt.Fprintln(os.Stderr, resp.Reason)
	}
	return nil
}

// postEvaluatePayload is the testable core of the PostToolUse handler.
// The optional trailing ag argument provides OTLP agent attribution; nil
// when omitted (test callers) so telemetry resource attrs are simply
// absent.
func postEvaluatePayload(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string, agOpt ...agent.Agent) (*HookResponse, error) {
	var ag agent.Agent
	if len(agOpt) > 0 {
		ag = agOpt[0]
	}
	// Verify session integrity — detect external tampering of session.json
	if !session.VerifySessionIntegrity(state) {
		state.SetDenyAll("session.json modified outside sir")
		if saveErr := state.Save(); saveErr != nil {
			fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
		}
		return &HookResponse{
			Decision: "deny",
			Reason:   FormatSessionIntegrityFatal(),
		}, nil
	}

	// If session is already in deny-all, return the fatal message on every call.
	if state.DenyAll {
		return &HookResponse{
			Decision: "deny",
			Reason:   FormatDenyAll(state.DenyAllReason),
		}, nil
	}

	rebaselinePostureHashesAfterWrite(payload, state, l, projectRoot)

	// If a Read or Grep of a sensitive path just completed, mark the session as secret.
	// This fires AFTER the user approved the ask prompt, so the read actually happened.
	// Use IsSensitivePathResolvedIn so symlinked paths and absolute paths are caught.
	sensitiveTarget := recordSensitiveTargetFromPostPayload(payload, l, projectRoot)
	if sensitiveTarget != "" && !state.SecretSession {
		recordSensitiveReadEvidence(state, sensitiveTarget)
		// Default to turn scope: the secret flag clears when the next turn begins.
		state.MarkSecretSession() // defaults to "turn" scope
		fmt.Fprintf(os.Stderr, "sir: credentials file read (%s). External network requests are now restricted.\n", sensitiveTarget)
		fmt.Fprintf(os.Stderr, "sir: this is turn-scoped — clears when the agent finishes responding.\n")
		fmt.Fprintf(os.Stderr, "sir: to clear now: sir unlock\n")
	} else if sensitiveTarget != "" {
		recordSensitiveReadEvidence(state, sensitiveTarget)
	}

	// Scan tool output for structured credentials in Read/Edit/Bash results.
	// MCP tool output is already scanned for injection further below — don't double-scan.
	// On match, escalate the IFC label by marking the session as secret (same effect as
	// approving a .env read). The consequence is restriction, not block.
	if payload.ToolOutput != "" && !isToolMCP(payload.ToolName) {
		switch payload.ToolName {
		case "Read", "Edit", "Bash":
			credMatches := ScanOutputForCredentials(payload.ToolOutput)
			if len(credMatches) > 0 {
				recordCredentialOutputEvidence(state, lineageSourceRef(payload, extractPostEvaluateTarget(payload)), credMatches)
				patternNames := make([]string, 0, len(credMatches))
				for _, m := range credMatches {
					patternNames = append(patternNames, m.PatternName)
				}
				if !state.SecretSession {
					state.MarkSecretSession()
					fmt.Fprintf(os.Stderr, "sir: structured credentials detected in %s output: %v\n", payload.ToolName, patternNames)
					fmt.Fprintf(os.Stderr, "sir: session marked secret — external network requests are now restricted.\n")
					fmt.Fprintf(os.Stderr, "sir: to lift: sir unlock\n")
				}
				entry := credentialOutputEntry(payload, extractPostEvaluateTarget(payload), patternNames, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
				if err := ledger.Append(projectRoot, entry); err != nil {
					fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
				}
				emitTelemetryEvent(entry, state, ag)
			}
		}
	}

	// Check 1: If we had a pending install, compare sentinel hashes
	if state.PendingInstall != nil && payload.ToolName == "Bash" {
		changed := checkPendingInstall(state, l, projectRoot)
		if len(changed) > 0 {
			entry := sentinelMutationEntry(payload, state.PendingInstall.Command, changed)
			if err := ledger.Append(projectRoot, entry); err != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			}
			emitTelemetryEvent(entry, state, ag)
		}
		state.ClearPendingInstall()
	}

	if resp, handled := handleBashPostEvaluateChecks(payload, l, state, projectRoot, ag); handled {
		return resp, nil
	}

	// Scan MCP tool responses for prompt injection signals.
	// Only scan mcp__* tools with non-empty output.
	if isToolMCP(payload.ToolName) && payload.ToolOutput != "" {
		serverName := extractMCPServerName(payload.ToolName)
		mcpCredMatches := ScanOutputForCredentials(payload.ToolOutput)
		if len(mcpCredMatches) > 0 {
			recordMCPCredentialEvidence(state, lineageSourceRef(payload, serverName), mcpCredMatches)
			patternNames := make([]string, 0, len(mcpCredMatches))
			for _, m := range mcpCredMatches {
				patternNames = append(patternNames, m.PatternName)
			}
			if !state.SecretSession {
				state.MarkSecretSession()
				fmt.Fprintf(os.Stderr, "sir: structured credentials detected in %s output.\n", payload.ToolName)
				fmt.Fprintf(os.Stderr, "sir: session marked secret — external network requests are now restricted.\n")
				fmt.Fprintf(os.Stderr, "sir: to lift: sir unlock\n")
			}
			entry := mcpCredentialOutputEntry(payload, serverName, patternNames, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
			if err := ledger.Append(projectRoot, entry); err != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			}
			emitTelemetryEvent(entry, state, ag)
		}

		signals := ScanMCPResponseForInjection(payload.ToolOutput)
		if len(signals) > 0 {
			severity := HighestSeverity(signals)
			recordMCPInjectionEvidence(state, lineageSourceRef(payload, serverName), severity)

			// Record signals and tainted server in session state
			for _, sig := range signals {
				state.AddMCPInjectionSignal(sig.Pattern)
			}
			state.AddTaintedMCPServer(serverName)

			// Raise posture based on severity
			switch severity {
			case "HIGH":
				state.RaisePosture(policy.PostureStateCritical)
			case "MEDIUM":
				state.RaisePosture(policy.PostureStateElevated)
			default:
				state.RaisePosture(policy.PostureStateElevated)
			}

			// Mark untrusted read — the response content is untrusted
			state.MarkUntrustedRead()

			// Log to ledger (never log the actual output content)
			var patternNames []string
			for _, sig := range signals {
				patternNames = append(patternNames, sig.Pattern)
			}
			entry := mcpInjectionEntry(payload, serverName, patternNames, severity, redactToolOutputEvidenceIfEnabled(payload.ToolOutput))
			if err := ledger.Append(projectRoot, entry); err != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			}
			emitTelemetryEvent(entry, state, ag)

			// Set pending injection alert so the next PreToolUse intercepts
			// and asks the developer before processing the tool call.
			// This closes the one-action window between detection and enforcement.
			if severity == "HIGH" {
				state.SetPendingInjectionAlert(fmt.Sprintf("MCP server %s returned prompt injection signals: %v", serverName, patternNames))
			}

			// Warn on stderr so the developer sees it in Claude Code context
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintln(os.Stderr, FormatMCPInjectionWarning(serverName, severity, patternNames))
		}
	}

	if payload.ToolName == "Write" || payload.ToolName == "Edit" {
		attachLineageToWriteTarget(projectRoot, state, payload)
	}

	return &HookResponse{Decision: policy.VerdictAllow}, nil
}

// checkPendingInstall re-hashes sentinel files after an install and returns changed files.
func checkPendingInstall(state *session.State, l *lease.Lease, projectRoot string) []string {
	if state.PendingInstall == nil {
		return nil
	}
	afterHashes := HashSentinelFiles(projectRoot, l.SentinelFilesForInstall)
	return CompareSentinelHashes(state.PendingInstall.SentinelHashes, afterHashes)
}
