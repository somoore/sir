package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func evaluateSessionIntegrityGuard(state *session.State) (*HookResponse, bool) {
	if session.VerifySessionIntegrity(state) {
		return nil, false
	}
	state.SetDenyAll("session.json modified outside sir")
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatSessionIntegrityFatal(),
	}, true
}

func evaluateDenyAllGuard(state *session.State) (*HookResponse, bool) {
	if !state.DenyAll {
		return nil, false
	}
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatDenyAll(state.DenyAllReason),
	}, true
}

func consumePendingInjectionAlert(state *session.State) string {
	if !state.PendingInjectionAlert {
		return ""
	}
	detail := state.InjectionAlertDetail
	state.ClearPendingInjectionAlert()
	saveSessionBestEffort(state)
	return detail
}

func delegationRequiresApproval(state *session.State) bool {
	if state.SecretSession {
		return false
	}
	if state.PendingInjectionAlert {
		return true
	}
	if state.Posture == policy.PostureStateElevated || state.Posture == policy.PostureStateCritical {
		return true
	}
	return len(state.TaintedMCPServers) > 0
}

func evaluateDelegationHardDeny(intent Intent, l *lease.Lease, state *session.State, ag agent.Agent) (*HookResponse, bool) {
	if intent.Verb != policy.VerbDelegate {
		return nil, false
	}

	if state.SecretSession {
		agentName := "Claude"
		if ag != nil {
			agentName = AgentDisplayName(string(ag.ID()))
		}
		saveSessionBestEffort(state)
		return &HookResponse{
			Decision: policy.VerdictDeny,
			Reason:   FormatBlockDelegation(agentName),
		}, true
	}

	if !l.AllowDelegation {
		saveSessionBestEffort(state)
		return &HookResponse{
			Decision: policy.VerdictDeny,
			Reason: FormatBlock(
				"sub-agent delegation",
				"Lease does not allow agent delegation (allow_delegation = false).",
				"Update lease to allow delegation: sir install",
			),
		}, true
	}

	return nil, false
}

func evaluateLeaseIntegrityGuard(projectRoot string, state *session.State) (*HookResponse, bool) {
	if VerifyLeaseIntegrity(projectRoot, state) {
		return nil, false
	}
	state.SetDenyAll("lease.json modified outside approved write")
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictDeny,
		Reason:   FormatLeaseIntegrityFatal(),
	}, true
}

func saveSessionBestEffort(state *session.State) {
	if err := state.Save(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", err)
	}
}
