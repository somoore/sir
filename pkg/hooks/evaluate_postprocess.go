package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func applyCoreEvaluationResult(coreResp *core.Response, intent Intent, labels core.Label, state *session.State, ag agent.Agent) *HookResponse {
	hookResp := &HookResponse{
		Decision: coreResp.Decision,
		Reason:   coreResp.Reason,
	}

	if coreResp.Decision == policy.VerdictAllow || coreResp.Decision == policy.VerdictAsk {
		if intent.IsSensitive && intent.Verb == policy.VerbReadRef {
			if coreResp.Decision == policy.VerdictAllow {
				state.MarkSecretSession()
			}
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

	if coreResp.Decision == policy.VerdictDeny {
		hookResp.Reason = formatDenyReason(coreResp.Reason, intent, state, ag)
	}
	return hookResp
}

func overlayPendingInjectionWarning(hookResp *HookResponse, pendingInjectionDetail string) {
	if pendingInjectionDetail == "" {
		return
	}
	injectionWarning := fmt.Sprintf("sir WARNING: A previous tool response contained suspicious patterns. %s", pendingInjectionDetail)
	switch hookResp.Decision {
	case policy.VerdictDeny:
		hookResp.Reason += "\n\n  Additionally: " + injectionWarning
	case policy.VerdictAllow:
		hookResp.Decision = policy.VerdictAsk
		hookResp.Reason = injectionWarning + "\n\n  This action would normally be allowed, but requires approval due to the suspicious activity."
	case policy.VerdictAsk:
		hookResp.Reason = injectionWarning + "\n\n  " + hookResp.Reason
	}
}
