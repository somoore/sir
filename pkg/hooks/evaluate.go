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
	if resp, handled := evaluateSessionIntegrityGuard(state); handled {
		return resp, nil
	}

	state.MaybeAdvanceTurn(time.Now())

	if resp, handled := evaluateDenyAllGuard(state); handled {
		return resp, nil
	}

	pendingInjectionDetail := consumePendingInjectionAlert(state)

	if resp, handled := evaluateLeaseIntegrityGuard(projectRoot, state); handled {
		return resp, nil
	}

	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
	labels := labelsForEvaluation(payload, intent, l, projectRoot)

	if resp, handled := evaluateMCPCredentialLeak(payload, l, state, projectRoot); handled {
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPServer(payload, state); handled {
		return resp, nil
	}

	if resp, handled := evaluateDelegationHardDeny(intent, l, state, ag); handled {
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, ag)
		return resp, nil
	}

	if intent.Verb == policy.VerbDelegate && (pendingInjectionDetail != "" || delegationRequiresApproval(state)) {
		resp := &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   FormatAskPostureElevated(string(intent.Verb), intent.Target, string(state.Posture), state.MCPInjectionSignals),
		}
		overlayPendingInjectionWarning(resp, pendingInjectionDetail)
		saveSessionBestEffort(state)
		appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, resp.Decision, resp.Reason, state, ag)
		return resp, nil
	}

	if resp, handled := evaluateTaintedMCPInput(payload, l, state, projectRoot); handled {
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

	hookResp := applyCoreEvaluationResult(coreResp, intent, labels, state, ag)
	overlayPendingInjectionWarning(hookResp, pendingInjectionDetail)

	if err := state.Save(); err != nil {
		return nil, fmt.Errorf("save session: %w", err)
	}

	appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, coreResp.Decision, coreResp.Reason, state, ag)

	return hookResp, nil
}
