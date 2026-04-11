package hooks

import (
	"fmt"
	"os"

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
