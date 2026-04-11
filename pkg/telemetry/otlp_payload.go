package telemetry

import (
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// otlpAnyValue mirrors the OTLP/HTTP JSON AnyValue type. Exactly one of
// the pointer fields is set per attribute, so omitempty produces a
// well-formed single-typed value.
type otlpAnyValue struct {
	StringValue *string `json:"stringValue,omitempty"`
	BoolValue   *bool   `json:"boolValue,omitempty"`
	IntValue    *string `json:"intValue,omitempty"` // OTLP encodes int64 as string
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScope struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type otlpLogRecord struct {
	TimeUnixNano         string         `json:"timeUnixNano"`
	ObservedTimeUnixNano string         `json:"observedTimeUnixNano"`
	SeverityNumber       int            `json:"severityNumber"`
	SeverityText         string         `json:"severityText"`
	Body                 otlpAnyValue   `json:"body"`
	Attributes           []otlpKeyValue `json:"attributes"`
}

type otlpScopeLogs struct {
	Scope      otlpScope       `json:"scope"`
	LogRecords []otlpLogRecord `json:"logRecords"`
}

type otlpResourceLogs struct {
	Resource  otlpResource    `json:"resource"`
	ScopeLogs []otlpScopeLogs `json:"scopeLogs"`
}

type otlpLogsRequest struct {
	ResourceLogs []otlpResourceLogs `json:"resourceLogs"`
}

func strAttr(key, val string) otlpKeyValue {
	v := val
	return otlpKeyValue{Key: key, Value: otlpAnyValue{StringValue: &v}}
}

func boolAttr(key string, val bool) otlpKeyValue {
	v := val
	return otlpKeyValue{Key: key, Value: otlpAnyValue{BoolValue: &v}}
}

func intAttr(key string, val int) otlpKeyValue {
	v := strconv.FormatInt(int64(val), 10)
	return otlpKeyValue{Key: key, Value: otlpAnyValue{IntValue: &v}}
}

// buildOTLPPayload renders a LogEvent into an OTLP/HTTP JSON request body.
// Empty string fields and false bool fields are omitted from the attribute
// list to keep the wire format compact and to preserve "exactly one type"
// semantics for each attribute that is included.
func buildOTLPPayload(ev LogEvent, sessionID, agentID, agentName, version string) ([]byte, error) {
	ev = sanitizeLogEvent(ev)
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	tsNano := strconv.FormatInt(ts.UnixNano(), 10)

	sevNum, sevText := severityFromEvent(ev)

	resourceAttrs := []otlpKeyValue{
		strAttr("service.name", "sir"),
		strAttr("service.version", version),
	}
	if sessionID != "" {
		resourceAttrs = append(resourceAttrs, strAttr("sir.session_id", sessionID))
	}
	// Agent attribution lives at resource level (not log-record level) so
	// SIEMs can filter an entire fleet by host agent without regex-scanning
	// every record.
	if agentID != "" {
		resourceAttrs = append(resourceAttrs, strAttr("sir.agent.id", agentID))
	}
	if agentName != "" {
		resourceAttrs = append(resourceAttrs, strAttr("sir.agent.name", agentName))
	}

	logAttrs := []otlpKeyValue{}
	if ev.ToolName != "" {
		logAttrs = append(logAttrs, strAttr("sir.tool_name", ev.ToolName))
	}
	if ev.Verb != "" {
		logAttrs = append(logAttrs, strAttr("sir.verb", ev.Verb))
	}
	if ev.Verdict != "" {
		logAttrs = append(logAttrs, strAttr("sir.verdict", ev.Verdict))
	}
	if ev.Target != "" {
		logAttrs = append(logAttrs, strAttr("sir.target", RedactTarget(ev.Target, ev.Sensitivity, ev.Verb)))
	}
	if ev.Reason != "" {
		logAttrs = append(logAttrs, strAttr("sir.reason", ev.Reason))
	}
	if ev.Sensitivity != "" {
		logAttrs = append(logAttrs, strAttr("sir.ifc.sensitivity", ev.Sensitivity))
	}
	if ev.Trust != "" {
		logAttrs = append(logAttrs, strAttr("sir.ifc.trust", ev.Trust))
	}
	if ev.Provenance != "" {
		logAttrs = append(logAttrs, strAttr("sir.ifc.provenance", ev.Provenance))
	}
	if ev.PostureState != "" {
		logAttrs = append(logAttrs, strAttr("sir.posture.state", ev.PostureState))
	}
	if ev.InjectionAlert {
		logAttrs = append(logAttrs, boolAttr("sir.posture.injection_alert", true))
	}
	if ev.MCPTaint {
		logAttrs = append(logAttrs, boolAttr("sir.posture.mcp_taint", true))
	}
	if ev.SecretSession {
		logAttrs = append(logAttrs, boolAttr("sir.session.secret", true))
	}
	if ev.LedgerHash != "" || ev.LedgerIndex != 0 {
		logAttrs = append(logAttrs, intAttr("sir.ledger.index", ev.LedgerIndex))
	}
	if ev.LedgerHash != "" {
		logAttrs = append(logAttrs, strAttr("sir.ledger.hash", ev.LedgerHash))
	}
	if ev.AlertType != "" {
		logAttrs = append(logAttrs, strAttr("sir.alert.type", ev.AlertType))
	}
	if ev.Severity != "" {
		logAttrs = append(logAttrs, strAttr("sir.alert.severity", ev.Severity))
	}
	if ev.Evidence != "" {
		logAttrs = append(logAttrs, strAttr("sir.evidence", ev.Evidence))
	}
	if ev.AlertAgentID != "" {
		logAttrs = append(logAttrs, strAttr("sir.alert.agent.id", ev.AlertAgentID))
	}
	if ev.DiffSummary != "" {
		logAttrs = append(logAttrs, strAttr("sir.alert.diff_summary", ev.DiffSummary))
	}
	if ev.Restored {
		logAttrs = append(logAttrs, boolAttr("sir.alert.restored", true))
	}

	body := fmt.Sprintf("sir %s %s %s", ev.Verdict, ev.Verb, ev.ToolName)
	bodyVal := body

	rec := otlpLogRecord{
		TimeUnixNano:         tsNano,
		ObservedTimeUnixNano: tsNano,
		SeverityNumber:       sevNum,
		SeverityText:         sevText,
		Body:                 otlpAnyValue{StringValue: &bodyVal},
		Attributes:           logAttrs,
	}

	req := otlpLogsRequest{
		ResourceLogs: []otlpResourceLogs{{
			Resource: otlpResource{Attributes: resourceAttrs},
			ScopeLogs: []otlpScopeLogs{{
				Scope:      otlpScope{Name: "sir.hooks", Version: version},
				LogRecords: []otlpLogRecord{rec},
			}},
		}},
	}

	return json.Marshal(req)
}
