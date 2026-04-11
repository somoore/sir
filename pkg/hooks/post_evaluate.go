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

	applyPostEvaluateOutputCredentialAnalysis(payload, state, projectRoot, ag)
	propagateBashLineageMutation(projectRoot, state, payload)

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

	applyPostEvaluateMCPOutputAnalysis(payload, state, projectRoot, ag)

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
