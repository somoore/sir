package hooks

import (
	"fmt"
	"os"
	"time"

	"github.com/somoore/sir/pkg/agent"
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

	// Load or create session under file lock.
	// The lock covers the entire Load→Evaluate(mutate)→Save pipeline so
	// concurrent PreToolUse/PostToolUse hooks cannot corrupt session state.
	var l *lease.Lease
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		var leaseMeta leaseLoadMetadata
		l, leaseMeta, err = loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, sErr := loadOrCreateSession(projectRoot, l, leaseMeta)
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

// EvaluatePermissionRequest handles agents that expose a distinct
// PermissionRequest hook. The policy path is intentionally the same as
// PreToolUse so a permission prompt cannot gain broader authority than the
// tool call it represents.
func EvaluatePermissionRequest(projectRoot string, ag agent.Agent) error {
	payload, err := readPayload(os.Stdin, ag)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	var l *lease.Lease
	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		var leaseMeta leaseLoadMetadata
		l, leaseMeta, err = loadLeaseWithMetadata(projectRoot)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		state, sErr := loadOrCreateSession(projectRoot, l, leaseMeta)
		if sErr != nil {
			return fmt.Errorf("load session: %w", sErr)
		}
		var eErr error
		resp, eErr = evaluatePayload(payload, l, state, projectRoot, ag)
		return eErr
	})
	if lockErr != nil {
		return fmt.Errorf("evaluate permission request: %w", lockErr)
	}

	return writePermissionRequestResponse(os.Stdout, resp, ag)
}

// evaluatePayload is the testable core of the PreToolUse handler.
//
// The optional trailing ag argument is used for OTLP telemetry attribution
// (sir.agent.id / sir.agent.name resource attributes). Variadic rather than
// a required parameter so the dozens of existing test callers don't need
// to be touched; when omitted, agent attribution is simply absent from the
// telemetry payload.
func evaluatePayload(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string, agOpt ...agent.Agent) (resp *HookResponse, err error) {
	var ag agent.Agent
	if len(agOpt) > 0 {
		ag = agOpt[0]
	}
	state.DecisionStartedAt = time.Now()
	if r, handled := evaluateSessionIntegrityGuard(state); handled {
		return r, nil
	}

	state.MaybeAdvanceTurn(time.Now())

	if r, handled := evaluateDenyAllGuard(state); handled {
		return r, nil
	}

	pendingInjectionDetail := consumePendingInjectionAlert(state)

	if r, handled := evaluateLeaseIntegrityGuard(projectRoot, state); handled {
		return r, nil
	}

	// Observe-only rollout: from here on, nothing blocks. The would-be verdict
	// is recorded in the ledger as a would_* decision (with detection IDs), and
	// the wire response is downgraded to allow on every return path below. The
	// control-plane integrity guards above run first and are never suppressed.
	if l != nil && l.ObserveOnly {
		defer func() {
			if err == nil {
				applyObserveMode(resp)
			}
		}()
	}

	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
	labels := labelsForEvaluation(payload, intent, l, projectRoot)

	if resp, handled := evaluateRawSecretReadGate(payload, intent, labels, l, state, projectRoot, ag); handled {
		return resp, nil
	}

	if resp, handled := evaluateMCPCredentialLeak(payload, l, state, projectRoot); handled {
		return resp, nil
	}

	if resp, handled := evaluateMCPCapabilityScope(payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPServer(payload, state); handled {
		return resp, nil
	}

	if resp, handled := evaluateDelegationHardDeny(intent, l, state, ag); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	if intent.Verb == policy.VerbDelegate && (pendingInjectionDetail != "" || delegationRequiresApproval(state)) {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   FormatAskPostureElevated(string(intent.Verb), intent.Target, string(state.Posture), state.MCPInjectionSignals),
		}
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		saveSessionBestEffort(state)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, l.ObserveOnly, ag)
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPInput(payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateMCPBinaryDrift(intent, payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateMCPOnboarding(intent, payload, l, state, projectRoot); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		return resp, nil
	}

	if resp, handled := evaluateElevatedPosture(intent, state); handled {
		return resp, nil
	}

	if resp, handled := prepareInstallEvaluation(intent, state, l, projectRoot); handled {
		return resp, nil
	}

	coreResp, err := evaluatePolicy(projectRoot, payload, intent, l, state, labels)
	if err != nil {
		return nil, err
	}
	if coreResp.Decision == policy.VerdictAsk {
		if grant, ok := state.ConsumeApprovalGrant(string(intent.Verb), intent.Target); ok {
			coreResp.Decision = policy.VerdictAllow
			if grant.Reason != "" {
				coreResp.Reason = "manual approval grant: " + grant.Reason
			} else {
				coreResp.Reason = "manual approval grant"
			}
		}
	}

	hookResp := applyCoreEvaluationResult(coreResp, intent, labels, state, ag)
	overlayPendingInjectionWarning(hookResp, pendingInjectionDetail)

	// Track repeated prompts/blocks for the same intent so repeated_denied_intent
	// fires in real time and the egress escalation can see repetition. Recorded
	// before Save so the increment persists; stamping reads the count after.
	if coreResp.Decision == policy.VerdictDeny || coreResp.Decision == policy.VerdictAsk {
		state.RecordPromptedIntent(promptKey(intent.Verb, intent.Target))
	}
	maybeMarkAutoLeasePending(l, state, intent, coreResp.Decision)

	if err := state.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, coreResp.Decision, coreResp.Reason, state, l.ObserveOnly, ag)

	return hookResp, nil
}
