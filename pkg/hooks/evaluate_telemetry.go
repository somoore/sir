package hooks

import (
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
	exporter := telemetry.NewExporter(state.ProjectRoot, state.SessionID, agentID, agentName)
	exporter.Emit(buildLogEvent(entry, state))
	exporter.Shutdown()
}

// buildLogEvent translates a ledger Entry plus session State into a telemetry LogEvent.
func buildLogEvent(entry *ledger.Entry, state *session.State) telemetry.LogEvent {
	return telemetry.LogEvent{
		Timestamp:      entry.Timestamp,
		SessionID:      state.SessionID,
		ToolName:       entry.ToolName,
		Verb:           entry.Verb,
		Verdict:        entry.Decision,
		Sensitivity:    entry.Sensitivity,
		Trust:          entry.Trust,
		Provenance:     entry.Provenance,
		Target:         entry.Target,
		Reason:         entry.Reason,
		PostureState:   string(state.Posture),
		InjectionAlert: state.PendingInjectionAlert,
		MCPTaint:       len(state.TaintedMCPServers) > 0,
		SecretSession:  state.SecretSession,
		LedgerIndex:    entry.Index,
		LedgerHash:     entry.EntryHash,
		AlertType:      entry.AlertType,
		Severity:       entry.Severity,
		Evidence:       entry.Evidence,
		AlertAgentID:   entry.Agent,
		DiffSummary:    entry.DiffSummary,
		Restored:       entry.Restored,
	}
}
