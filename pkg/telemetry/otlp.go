// Package telemetry implements optional OTLP/HTTP JSON log export for sir.
//
// Telemetry is fire-and-forget and entirely opt-in: when the environment
// variable SIR_OTLP_ENDPOINT is unset, every exported method is a no-op and
// no goroutines, sockets, or allocations beyond the LogEvent itself are
// created. When set, sir will POST a single OTLP/HTTP log record per Emit
// call to <endpoint>/v1/logs with a 200ms HTTP client timeout.
//
// This package has zero external dependencies (Go stdlib only) per the sir
// implementation rules. It NEVER serializes raw secret file contents. When
// investigation evidence is enabled, only redacted evidence slices are
// emitted alongside verdict metadata.
package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/somoore/sir/pkg/ledger"
)

// Version is the sir telemetry schema version reported as service.version.
const Version = "2.0.0"

const (
	defaultQueueSize   = 32
	defaultWorkerCount = 2
)

// LogEvent is a normalized record of a single sir hook decision suitable for
// OTLP export. All fields are optional; zero values are omitted from the
// emitted payload via omitempty on the OTLP attribute encoding.
type LogEvent struct {
	Timestamp      time.Time
	SessionID      string
	ToolName       string
	Verb           string
	Verdict        string
	Sensitivity    string
	Trust          string
	Provenance     string
	Target         string
	Reason         string
	PostureState   string
	InjectionAlert bool
	MCPTaint       bool
	SecretSession  bool
	LedgerIndex    int
	LedgerHash     string
	AlertType      string
	Severity       string
	Evidence       string
	AlertAgentID   string
	DiffSummary    string
	Restored       bool
}

// Exporter is a fire-and-forget OTLP/HTTP JSON log exporter. The zero value
// is not usable; construct one with NewExporter. When SIR_OTLP_ENDPOINT is
// unset the exporter is in no-op mode and Emit/Shutdown return immediately.
type Exporter struct {
	mu          sync.Mutex
	projectRoot string
	endpoint    string
	sessionID   string
	agentID     string
	agentName   string
	client      *http.Client
	enabled     bool
	closed      bool
	queue       chan LogEvent
	queueSize   int
	workerCount int
	workers     sync.WaitGroup
	dropped     atomic.Uint64
	queued      atomic.Uint64
}

// NewExporter constructs a telemetry exporter for the given session and host
// agent. If SIR_OTLP_ENDPOINT is empty or invalid the returned exporter is a
// no-op. The HTTP client is configured with a 200ms timeout so a slow
// collector can never block hook evaluation.
//
// agentID and agentName are emitted as resource-level attributes
// (sir.agent.id, sir.agent.name) so SIEMs can filter telemetry by host
// agent. Callers should pass the adapter's ID/Name; empty strings are
// allowed for backward compatibility (the attributes are simply omitted).
func NewExporter(projectRoot, sessionID, agentID, agentName string) *Exporter {
	return newExporterWithConfig(projectRoot, sessionID, agentID, agentName, strings.TrimSpace(os.Getenv("SIR_OTLP_ENDPOINT")), &http.Client{Timeout: 200 * time.Millisecond}, defaultQueueSize, defaultWorkerCount)
}

func newExporterWithConfig(projectRoot, sessionID, agentID, agentName, endpoint string, client *http.Client, queueSize, workerCount int) *Exporter {
	ex := &Exporter{
		projectRoot: projectRoot,
		sessionID:   sessionID,
		agentID:     agentID,
		agentName:   agentName,
	}
	if endpoint == "" {
		return ex
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return ex
	}
	if queueSize <= 0 {
		queueSize = defaultQueueSize
	}
	if workerCount <= 0 {
		workerCount = defaultWorkerCount
	}
	if client == nil {
		client = &http.Client{Timeout: 200 * time.Millisecond}
	}
	ex.endpoint = strings.TrimRight(endpoint, "/")
	ex.client = client
	ex.enabled = true
	ex.queue = make(chan LogEvent, queueSize)
	ex.queueSize = queueSize
	ex.workerCount = workerCount
	for i := 0; i < workerCount; i++ {
		ex.workers.Add(1)
		go ex.runWorker()
	}
	return ex
}

// Emit asynchronously POSTs a single log record to the configured OTLP
// endpoint. Returns immediately. Errors during transport are intentionally
// swallowed: telemetry must never affect sir's enforcement path.
func (e *Exporter) Emit(ev LogEvent) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.enabled || e.closed {
		return
	}
	select {
	case e.queue <- ev:
		e.queued.Add(1)
	default:
		e.dropped.Add(1)
	}
}

func (e *Exporter) runWorker() {
	defer e.workers.Done()
	for ev := range e.queue {
		payload, err := buildOTLPPayload(ev, e.sessionID, e.agentID, e.agentName, Version)
		if err != nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+"/v1/logs", bytes.NewReader(payload))
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := e.client.Do(req)
		cancel()
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
	}
}

// DroppedCount reports how many events were dropped because the in-process
// exporter queue was already full.
func (e *Exporter) DroppedCount() uint64 {
	if e == nil {
		return 0
	}
	return e.dropped.Load()
}

// Shutdown signals the exporter to stop accepting new emissions and waits up
// to 500ms for queued work to drain. Always safe to call; safe on a nil
// receiver.
func (e *Exporter) Shutdown() {
	if e == nil {
		return
	}
	e.mu.Lock()
	enabled := e.enabled
	if !enabled || e.closed {
		queueSize := e.queueSize
		workerCount := e.workerCount
		e.mu.Unlock()
		_ = recordHealth(e.projectRoot, enabled, queueSize, workerCount, e.queued.Load(), e.dropped.Load(), time.Now())
		return
	}
	e.closed = true
	queueSize := e.queueSize
	workerCount := e.workerCount
	close(e.queue)
	e.mu.Unlock()

	waitCh := make(chan struct{})
	go func() {
		e.workers.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
	case <-time.After(500 * time.Millisecond):
	}
	_ = recordHealth(e.projectRoot, enabled, queueSize, workerCount, e.queued.Load(), e.dropped.Load(), time.Now())
}

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
	if ev.LedgerIndex > 0 {
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

func sanitizeLogEvent(ev LogEvent) LogEvent {
	ev.Reason = ledger.RedactString(ev.Reason)
	ev.Evidence = ledger.RedactEvidence(ev.Evidence)
	ev.DiffSummary = ledger.RedactString(ev.DiffSummary)
	return ev
}

// RedactTarget returns a privacy-preserving form of a target path or URL
// suitable for telemetry. Secret-labeled targets are reduced to a sha256
// hash prefix; network verbs are reduced to hostname only; everything else
// is returned unchanged. The redaction rules ensure no secret content,
// query strings, or full filesystem paths leave the host.
func RedactTarget(target, sensitivity, verb string) string {
	if target == "" {
		return ""
	}
	if sensitivity == "secret" {
		sum := sha256.Sum256([]byte(target))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	switch verb {
	case "net_external", "net_allowlisted", "net_local", "dns_lookup", "push_origin", "push_remote":
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Hostname()
		}
		// Fall back to stripping scheme and path manually for bare host:port
		s := target
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		if i := strings.IndexAny(s, "/?#"); i >= 0 {
			s = s[:i]
		}
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = s[:i]
		}
		return s
	}
	return target
}

// severityFromEvent maps a sir verdict + alert severity to OTLP severity
// number and text. The mapping intentionally compresses sir's verdict space
// onto the OTLP severity ladder so collectors can filter by standard fields:
//
//	HIGH alert      -> 17 ERROR
//	MEDIUM | deny   -> 13 WARN
//	ask             ->  9 INFO
//	allow / other   ->  5 DEBUG
func severityFromEvent(ev LogEvent) (int, string) {
	if strings.EqualFold(ev.Severity, "HIGH") {
		return 17, "ERROR"
	}
	if strings.EqualFold(ev.Severity, "MEDIUM") || strings.EqualFold(ev.Verdict, "deny") {
		return 13, "WARN"
	}
	if strings.EqualFold(ev.Verdict, "ask") {
		return 9, "INFO"
	}
	return 5, "DEBUG"
}
