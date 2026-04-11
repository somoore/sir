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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
