package hooks

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/detect"
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

// promptKey is the stable session-counter key for a verb/target intent. The
// NUL separator avoids collisions between a verb and a target that share text.
func promptKey(verb policy.Verb, target string) string {
	return string(verb) + "\x00" + target
}

func appendEvaluationLedgerEntry(projectRoot string, payload *HookPayload, intent Intent, labels core.Label, decision policy.Verdict, reason string, state *session.State, observe bool, ag agent.Agent) {
	recorded := decision
	if observe {
		recorded = observeRecordedDecision(decision)
	}
	preview := ledger.RedactPreview(intent.Target, labels.Sensitivity == "secret")
	entry := &ledger.Entry{
		ToolName:    payload.ToolName,
		Verb:        string(intent.Verb),
		Target:      intent.Target,
		Sensitivity: labels.Sensitivity,
		Trust:       labels.Trust,
		Provenance:  labels.Provenance,
		Decision:    string(recorded),
		Reason:      reason,
		Preview:     preview,
	}
	if isToolMCP(payload.ToolName) && EnvLogToolContent() {
		entry.Evidence = marshalMCPEvidence(payload.ToolInput)
	}
	entry.LatencyMs = decisionLatencyMs(state)
	stampStatefulDetection(projectRoot, payload, intent, labels, recorded, state, entry)
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
	emitTelemetryEvent(entry, state, ag)
}

// stampStatefulDetection sets a detection ID that depends on session context
// the bare ledger entry cannot see (secret-session egress, secret-derived
// lineage, MCP taint). It runs only for blocked verdicts on the relevant
// verbs, so normal allow-path commits and pushes never pay for the lineage
// lookup. Entry-local detections (alerts, drift, onboarding) are stamped
// later inside ledger.Append.
// mcpAuthorityChangeWindow bounds how long after an MCP trust change a
// privileged action is correlated into mcp_change_then_privileged_use.
const mcpAuthorityChangeWindow = 30 * time.Minute

func stampStatefulDetection(projectRoot string, payload *HookPayload, intent Intent, labels core.Label, decision policy.Verdict, state *session.State, entry *ledger.Entry) {
	// Allowed actions normally carry no stateful detection — except a
	// privileged use shortly after an MCP trust change, which is the compound
	// supply-chain signal and must surface even when the action is allowed.
	if decision == policy.VerdictAllow && !state.RecentMCPAuthorityChange(mcpAuthorityChangeWindow) {
		return
	}
	derivedFromSecret := false
	if !state.SecretSession {
		for _, l := range derivedLabelsForIntent(projectRoot, payload, intent, state) {
			if l.Sensitivity == "secret" {
				derivedFromSecret = true
				break
			}
		}
	}
	priorRepeats := state.PromptCount(promptKey(intent.Verb, intent.Target)) - 1
	if priorRepeats < 0 {
		priorRepeats = 0
	}
	d, ok := detect.Classify(detect.Signal{
		Verb:              string(intent.Verb),
		Verdict:           string(decision),
		Sensitivity:       labels.Sensitivity,
		SecretSession:     state.SecretSession,
		DerivedFromSecret: derivedFromSecret,
		MCPTaint:          len(state.TaintedMCPServers) > 0,
		InjectionAlert:    state.PendingInjectionAlert,
		DenyAll:           state.DenyAll,
		RepeatedCount:     priorRepeats,
		RecentMCPChange:   state.RecentMCPAuthorityChange(mcpAuthorityChangeWindow),
		Suspicious:        state.IsSuspicious(),
	})
	if !ok {
		return
	}
	entry.DetectionID = string(d.ID)
	entry.DetectionRoute = d.Route.String()
	if entry.Severity == "" {
		entry.Severity = string(d.Severity)
	}
}
