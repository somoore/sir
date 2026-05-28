package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/agent"
	hookmessages "github.com/somoore/sir/pkg/hooks/messages"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// autoLeaseTTL bounds an auto-minted host lease. It is deliberately short: the
// goal is to stop the same host re-prompting within a working window, not to
// grant durable access.
const autoLeaseTTL = 15 * time.Minute

// isAutoLeaseableEgress reports whether a verb is a host-bearing egress ask
// that auto-leasing can resolve into an allow-host lease. net_external covers
// tightened policies that gate raw egress; mcp_network_unapproved is the
// default-config ask when an approved MCP tool reaches an unapproved host.
func isAutoLeaseableEgress(verb policy.Verb) bool {
	return verb == policy.VerbNetExternal || verb == policy.VerbMcpNetworkUnapproved
}

// autoLeaseSafeContext reports whether session posture is clean enough to
// auto-lease. Auto-leasing is a friction feature and is never applied while the
// session carries secret context, elevated posture, MCP taint, or a pending
// injection alert.
func autoLeaseSafeContext(state *session.State) bool {
	if state.SecretSession || state.PendingInjectionAlert {
		return false
	}
	if state.Posture != "" && state.Posture != policy.PostureStateNormal {
		return false
	}
	return len(state.TaintedMCPServers) == 0
}

// maybeMarkAutoLeasePending records a pending auto-lease when a clean external-
// egress ask is returned. The marker is only redeemed if the developer then
// approves and the tool executes (observed at PostToolUse).
func maybeMarkAutoLeasePending(l *lease.Lease, state *session.State, intent Intent, decision policy.Verdict) {
	if l == nil || !l.AutoLeaseApprovedHosts || decision != policy.VerdictAsk {
		return
	}
	if !isAutoLeaseableEgress(intent.Verb) || !autoLeaseSafeContext(state) {
		return
	}
	if host, ok := hookmessages.ExtractHostForMessage(intent.Target); ok {
		state.MarkPendingAutoLease(host)
	}
}

// applyAutoLeaseOnApproval mints a short TTL host lease when a previously-asked
// external egress is observed to have executed. A PostToolUse only fires if the
// developer approved the ask and the tool ran, so execution is a reliable
// consent signal — far safer than counting raw prompts. Returns true when a
// lease was minted.
func applyAutoLeaseOnApproval(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string, ag agent.Agent) bool {
	if l == nil || !l.AutoLeaseApprovedHosts || !autoLeaseSafeContext(state) {
		return false
	}
	// Never auto-write the lease under an org-managed policy, which pins the
	// lease hash; a local write would trip managed verification.
	if mp, err := session.LoadManagedPolicy(); err == nil && mp != nil {
		return false
	}
	intent := MapToolToIntent(payload.ToolName, payload.ToolInput, l)
	if !isAutoLeaseableEgress(intent.Verb) {
		return false
	}
	host, ok := hookmessages.ExtractHostForMessage(intent.Target)
	if !ok || host == "" {
		return false
	}
	if !state.ConsumePendingAutoLease(host) {
		return false
	}
	if err := mintAutoHostLease(projectRoot, l, state, host); err != nil {
		fmt.Fprintf(os.Stderr, "sir: auto-lease failed: %v\n", err)
		return false
	}
	expiry := time.Now().Add(autoLeaseTTL)
	entry := &ledger.Entry{
		ToolName: payload.ToolName,
		Verb:     "lease_modify",
		Target:   "approved_hosts",
		Decision: "allow",
		Reason:   fmt.Sprintf("auto-leased %s for %s after approved external egress", host, autoLeaseTTL),
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	emitTelemetryEvent(entry, state, ag)
	fmt.Fprintf(os.Stderr, "sir: you approved egress to %s — auto-leased it for %s (expires %s). Review: sir policy show\n",
		host, autoLeaseTTL, expiry.Format("15:04:05"))
	return true
}

// mintAutoHostLease adds host to the lease with a short TTL and refreshes the
// session lease-integrity baseline so the next call does not fail closed. It
// mirrors the CLI's atomic lease+baseline write (save lease, rehash, save
// session, roll back on failure) and must be called while holding the session
// lock — which both hook paths already do.
func mintAutoHostLease(projectRoot string, l *lease.Lease, state *session.State, host string) error {
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	original, origErr := lease.Load(leasePath)

	if !containsHost(l.ApprovedHosts, host) {
		l.ApprovedHosts = append(l.ApprovedHosts, host)
	}
	if l.ApprovedHostExpires == nil {
		l.ApprovedHostExpires = make(map[string]time.Time)
	}
	l.ApprovedHostExpires[strings.ToLower(host)] = time.Now().Add(autoLeaseTTL).UTC()

	if err := os.MkdirAll(filepath.Dir(leasePath), 0o700); err != nil {
		return err
	}
	if err := l.Save(leasePath); err != nil {
		return err
	}
	newHash, err := HashLease(projectRoot)
	if err != nil {
		rollbackLease(original, origErr, leasePath)
		return err
	}
	state.LeaseHash = newHash
	if err := state.Save(); err != nil {
		rollbackLease(original, origErr, leasePath)
		return err
	}
	return nil
}

func rollbackLease(original *lease.Lease, origErr error, leasePath string) {
	if origErr != nil || original == nil {
		_ = os.Remove(leasePath)
		return
	}
	_ = original.Save(leasePath)
}

func containsHost(hosts []string, host string) bool {
	for _, h := range hosts {
		if strings.EqualFold(h, host) {
			return true
		}
	}
	return false
}
