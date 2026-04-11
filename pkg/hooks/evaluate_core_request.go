package hooks

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

var jsonMarshal = json.Marshal

func buildCoreRequest(projectRoot string, payload *HookPayload, intent Intent, l *lease.Lease, state *session.State, labels core.Label) (*core.Request, error) {
	leaseJSON, err := marshalCoreLease(l)
	if err != nil {
		return nil, err
	}

	derivedLabels := derivedLabelsForIntent(projectRoot, payload, intent, state)
	return &core.Request{
		ToolName:  payload.ToolName,
		LeaseJSON: leaseJSON,
		Intent: core.Intent{
			Verb:          intent.Verb,
			Target:        intent.Target,
			Labels:        []core.Label{labels},
			DerivedLabels: derivedLabels,
			IsPosture:     intent.IsPosture,
			IsSensitive:   intent.IsSensitive,
			IsDelegation:  payload.ToolName == "Agent",
			IsTripwire:    false,
		},
		Session: core.SessionInfo{
			SecretSession:         state.SecretSession,
			RecentlyReadUntrusted: state.RecentlyReadUntrusted,
			DenyAll:               state.DenyAll,
			ApprovalScope:         string(state.ApprovalScope),
			TurnCounter:           state.TurnCounter,
		},
	}, nil
}

func marshalCoreLease(v interface{}) ([]byte, error) {
	data, err := jsonMarshal(v)
	if err != nil {
		return nil, fmt.Errorf("marshal lease: %w", err)
	}
	return data, nil
}

func appendEvaluationLedgerEntry(projectRoot string, payload *HookPayload, intent Intent, labels core.Label, decision policy.Verdict, reason string, state *session.State, ag agent.Agent) {
	preview := ledger.RedactPreview(intent.Target, labels.Sensitivity == "secret")
	entry := &ledger.Entry{
		ToolName:    payload.ToolName,
		Verb:        string(intent.Verb),
		Target:      intent.Target,
		Sensitivity: labels.Sensitivity,
		Trust:       labels.Trust,
		Provenance:  labels.Provenance,
		Decision:    string(decision),
		Reason:      reason,
		Preview:     preview,
	}
	if isToolMCP(payload.ToolName) && EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	emitTelemetryEvent(entry, state, ag)
}
