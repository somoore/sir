package hooks

import (
	"fmt"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// observeRecordedDecision maps a real verdict to its observe-only ledger form.
// In observe mode every decision is hypothetical — nothing is enforced — so it
// is recorded as a would_* verdict. This lets `sir friction` and the SIEM
// distinguish "what sir would have done" from real enforcement, and lets a
// later flip to enforcement reuse the same telemetry.
func observeRecordedDecision(decision policy.Verdict) policy.Verdict {
	switch decision {
	case policy.VerdictDeny:
		return "would_deny"
	case policy.VerdictAsk:
		return "would_ask"
	case policy.VerdictAllow:
		return "would_allow"
	default:
		return decision
	}
}

// recordedDecisionFor returns the ledger decision string for a verdict,
// rewriting it to its would_* form under observe-only mode. Used by the early
// preflight gates (MCP credential leak, onboarding, binary drift) so their
// ledger entries read as would_deny/would_ask in an observe rollout instead of
// looking like enforced blocks in `sir friction` and the SIEM.
func recordedDecisionFor(l *lease.Lease, decision policy.Verdict) string {
	if l != nil && l.ObserveOnly {
		return string(observeRecordedDecision(decision))
	}
	return string(decision)
}

// applyObserveMode downgrades a blocking wire verdict to allow so the agent is
// never interrupted during an observe-only rollout. The would-be verdict is
// surfaced in the reason for transparency; the ledger already recorded the
// would_* decision. Control-plane integrity guards (session/lease integrity,
// deny-all) are intentionally evaluated before this is registered, so observe
// mode never silently proceeds past a compromised control plane.
func applyObserveMode(resp *HookResponse) {
	if resp == nil {
		return
	}
	if resp.Decision == policy.VerdictDeny || resp.Decision == policy.VerdictAsk {
		wouldBe := resp.Decision
		resp.Decision = policy.VerdictAllow
		resp.Reason = FormatObserveOnly(string(wouldBe), resp.Reason)
	}
}

// FormatObserveOnly renders the observe-mode reason annotation.
func FormatObserveOnly(wouldBe, reason string) string {
	if reason == "" {
		return fmt.Sprintf("observe-only: would %s (not enforced)", wouldBe)
	}
	return fmt.Sprintf("observe-only: would %s (not enforced) — %s", wouldBe, reason)
}
