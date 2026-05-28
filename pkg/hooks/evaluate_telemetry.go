package hooks

import (
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/telemetry"
)

// emitTelemetryEvent fires a single OTLP/HTTP log record for the given ledger entry.
func emitTelemetryEvent(entry *ledger.Entry, state *session.State, ag agent.Agent) {
	agentID, agentName := "", ""
	if ag != nil {
		agentID = string(ag.ID())
		agentName = ag.Name()
	}
	ev := buildLogEvent(entry, state)
	exporter := telemetry.NewExporter(state.ProjectRoot, state.SessionID, agentID, agentName)
	exporter.Emit(ev)
	exporter.Shutdown()

	// Curated Slack escalation for high-severity detections only. The relay
	// is a no-op unless SIR_SLACK_WEBHOOK is set, and only fires for
	// Slack-routed detections, so normal coding never reaches a channel.
	telemetry.NewSlackRelay().MaybeNotify(ev)
}

// buildLogEvent translates a ledger Entry plus session State into a telemetry LogEvent.
func buildLogEvent(entry *ledger.Entry, state *session.State) telemetry.LogEvent {
	return telemetry.LogEvent{
		Timestamp:         entry.Timestamp,
		SessionID:         state.SessionID,
		ProjectHash:       session.ProjectHash(state.ProjectRoot),
		ToolName:          entry.ToolName,
		Verb:              entry.Verb,
		Verdict:           entry.Decision,
		Sensitivity:       entry.Sensitivity,
		Trust:             entry.Trust,
		Provenance:        entry.Provenance,
		Target:            entry.Target,
		Reason:            entry.Reason,
		PostureState:      string(state.Posture),
		InjectionAlert:    state.PendingInjectionAlert,
		MCPTaint:          len(state.TaintedMCPServers) > 0,
		SecretSession:     state.SecretSession,
		Suspicious:        state.IsSuspicious(),
		LedgerIndex:       entry.Index,
		LedgerHash:        entry.EntryHash,
		AlertType:         entry.AlertType,
		DetectionID:       entry.DetectionID,
		Route:             entry.DetectionRoute,
		Severity:          entry.Severity,
		Evidence:          entry.Evidence,
		AlertAgentID:      entry.Agent,
		DiffSummary:       entry.DiffSummary,
		Restored:          entry.Restored,
		LeaseVersion:      leaseVersion(state.LeaseHash),
		DecisionLatencyMs: decisionLatencyMs(state),
	}
}

// decisionLatencyMs returns how long the current decision has taken so far, or
// 0 when the start time was not recorded (e.g. PostToolUse lifecycle entries).
func decisionLatencyMs(state *session.State) int {
	if state.DecisionStartedAt.IsZero() {
		return 0
	}
	ms := time.Since(state.DecisionStartedAt).Milliseconds()
	if ms < 0 {
		return 0
	}
	return int(ms)
}

// leaseVersion renders a short, stable identifier for the active lease from
// its content hash. The lease is sir's authority contract, so its hash is the
// most honest "policy version" the SIEM can pivot on.
func leaseVersion(leaseHash string) string {
	if len(leaseHash) > 12 {
		return leaseHash[:12]
	}
	return leaseHash
}
