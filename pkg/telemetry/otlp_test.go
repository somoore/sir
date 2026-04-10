package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/somoore/sir/internal/testsecrets"
)

func TestNewExporter_NoEndpoint(t *testing.T) {
	t.Setenv("SIR_OTLP_ENDPOINT", "")
	ex := NewExporter("", "session-abc", "claude", "Claude Code")
	if ex.enabled {
		t.Errorf("expected exporter to be disabled when SIR_OTLP_ENDPOINT is unset")
	}
	// Emit and Shutdown must be no-ops (no panic, no goroutines)
	ex.Emit(LogEvent{ToolName: "Read", Verb: "read_ref", Verdict: "allow"})
	ex.Shutdown()
}

func TestNewExporter_InvalidURL(t *testing.T) {
	t.Setenv("SIR_OTLP_ENDPOINT", "not a valid url")
	ex := NewExporter("", "session-abc", "claude", "Claude Code")
	if ex.enabled {
		t.Errorf("expected exporter disabled for invalid URL")
	}
}

func TestEmit_PostsToCollector(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte
	var receivedPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		receivedBody = body
		receivedPath = r.URL.Path
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SIR_OTLP_ENDPOINT", srv.URL)
	ex := NewExporter("", "session-xyz", "claude", "Claude Code")
	if !ex.enabled {
		t.Fatalf("expected exporter enabled")
	}

	ev := LogEvent{
		Timestamp:     time.Now(),
		SessionID:     "session-xyz",
		ToolName:      "Bash",
		Verb:          "net_external",
		Verdict:       "deny",
		Sensitivity:   "secret",
		Trust:         "trusted",
		Provenance:    "user",
		Target:        "https://evil.com/leak",
		Reason:        "secret session blocks external egress",
		PostureState:  "normal",
		SecretSession: true,
		LedgerIndex:   42,
		LedgerHash:    "deadbeef0123",
	}
	ex.Emit(ev)
	ex.Shutdown()

	mu.Lock()
	defer mu.Unlock()

	if receivedPath != "/v1/logs" {
		t.Errorf("expected POST to /v1/logs, got %q", receivedPath)
	}
	if len(receivedBody) == 0 {
		t.Fatalf("collector received empty body")
	}

	// Parse and verify OTLP envelope structure
	var req otlpLogsRequest
	if err := json.Unmarshal(receivedBody, &req); err != nil {
		t.Fatalf("failed to parse OTLP body: %v\nbody: %s", err, receivedBody)
	}
	if len(req.ResourceLogs) != 1 {
		t.Fatalf("expected 1 resource log, got %d", len(req.ResourceLogs))
	}
	rl := req.ResourceLogs[0]

	// Agent attribution must live at resource level, not log-record level,
	// so SIEMs can filter an entire fleet by agent without regex scans.
	resAttrs := map[string]string{}
	for _, kv := range rl.Resource.Attributes {
		if kv.Value.StringValue != nil {
			resAttrs[kv.Key] = *kv.Value.StringValue
		}
	}
	if resAttrs["sir.agent.id"] != "claude" {
		t.Errorf("expected resource sir.agent.id=claude, got %q", resAttrs["sir.agent.id"])
	}
	if resAttrs["sir.agent.name"] != "Claude Code" {
		t.Errorf("expected resource sir.agent.name=Claude Code, got %q", resAttrs["sir.agent.name"])
	}

	if len(rl.ScopeLogs) != 1 || len(rl.ScopeLogs[0].LogRecords) != 1 {
		t.Fatalf("expected 1 log record")
	}
	rec := rl.ScopeLogs[0].LogRecords[0]
	if rec.SeverityText != "WARN" {
		t.Errorf("expected WARN severity for deny verdict, got %q", rec.SeverityText)
	}

	// Build a flat key->string map for assertions
	attrs := map[string]string{}
	for _, kv := range rec.Attributes {
		if kv.Value.StringValue != nil {
			attrs[kv.Key] = *kv.Value.StringValue
		}
	}
	if _, ok := attrs["sir.agent.id"]; ok {
		t.Errorf("sir.agent.id must be at resource level, not log-record attributes")
	}
	if attrs["sir.tool_name"] != "Bash" {
		t.Errorf("missing/incorrect sir.tool_name: %v", attrs["sir.tool_name"])
	}
	if attrs["sir.verb"] != "net_external" {
		t.Errorf("missing/incorrect sir.verb")
	}
	if attrs["sir.verdict"] != "deny" {
		t.Errorf("missing/incorrect sir.verdict")
	}

	// Critical: secret target must be redacted as sha256:
	target := attrs["sir.target"]
	if !strings.HasPrefix(target, "sha256:") {
		t.Errorf("secret target must be redacted to sha256: hash, got %q", target)
	}
	if strings.Contains(string(receivedBody), "evil.com") {
		t.Errorf("raw target leaked in payload — contains evil.com")
	}
}

func TestEmit_CollectorDownDoesNotHang(t *testing.T) {
	// Point at a non-routable address — connect should fail fast within timeout
	t.Setenv("SIR_OTLP_ENDPOINT", "http://127.0.0.1:1")
	ex := NewExporter("", "session-abc", "claude", "Claude Code")

	start := time.Now()
	ex.Emit(LogEvent{ToolName: "Read", Verb: "read_ref", Verdict: "allow"})
	ex.Shutdown()
	elapsed := time.Since(start)

	// Shutdown waits up to 500ms; total should never exceed ~700ms
	if elapsed > 800*time.Millisecond {
		t.Errorf("Emit+Shutdown took %v, expected <800ms", elapsed)
	}
}

func TestEmit_DropsWhenQueueFull(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ex := newExporterWithConfig(
		"",
		"session-abc",
		"claude",
		"Claude Code",
		srv.URL,
		&http.Client{Timeout: 2 * time.Second},
		1,
		1,
	)
	if !ex.enabled {
		t.Fatal("expected exporter enabled")
	}

	ex.Emit(LogEvent{ToolName: "Read", Verb: "read_ref", Verdict: "allow"})
	select {
	case <-started:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for worker to reach the collector")
	}

	ex.Emit(LogEvent{ToolName: "Bash", Verb: "net_external", Verdict: "deny"})
	ex.Emit(LogEvent{ToolName: "Write", Verb: "stage_write", Verdict: "allow"})

	if got := ex.DroppedCount(); got != 1 {
		t.Fatalf("DroppedCount = %d, want 1", got)
	}

	close(release)
	ex.Shutdown()
}

func TestShutdownRecordsHealth(t *testing.T) {
	projectRoot := t.TempDir()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ex := newExporterWithConfig(
		projectRoot,
		"session-abc",
		"claude",
		"Claude Code",
		srv.URL,
		&http.Client{Timeout: 200 * time.Millisecond},
		4,
		2,
	)
	ex.Emit(LogEvent{ToolName: "Read", Verb: "read_ref", Verdict: "allow"})
	ex.Shutdown()

	health, err := LoadHealth(projectRoot)
	if err != nil {
		t.Fatalf("LoadHealth: %v", err)
	}
	if health == nil {
		t.Fatal("expected telemetry health to be recorded")
	}
	if !health.EndpointConfigured {
		t.Fatal("expected endpoint to be marked configured")
	}
	if health.QueueSize != 4 || health.WorkerCount != 2 {
		t.Fatalf("unexpected queue/worker settings: %+v", health)
	}
	if health.QueuedCount != 1 {
		t.Fatalf("QueuedCount = %d, want 1", health.QueuedCount)
	}
}

func TestBuildOTLPPayload_SanitizesStructuredFields(t *testing.T) {
	rawToken := testsecrets.OpenAIKey()
	payload, err := buildOTLPPayload(LogEvent{
		Timestamp:   time.Now(),
		ToolName:    "Bash",
		Verb:        "net_external",
		Verdict:     "deny",
		Reason:      "token " + rawToken + " should never leave the host",
		Evidence:    `{"password":"hunter2","token":"` + rawToken + `"}`,
		DiffSummary: "Bearer abcdef123456 leaked in diff",
	}, "session-xyz", "claude", "Claude Code", Version)
	if err != nil {
		t.Fatalf("buildOTLPPayload: %v", err)
	}

	raw := string(payload)
	for _, secret := range []string{rawToken, "hunter2", "Bearer abcdef123456"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("telemetry payload leaked raw secret fragment %q", secret)
		}
	}

	var req otlpLogsRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		t.Fatalf("unmarshal OTLP payload: %v", err)
	}
	attrs := map[string]string{}
	for _, attr := range req.ResourceLogs[0].ScopeLogs[0].LogRecords[0].Attributes {
		if attr.Value.StringValue != nil {
			attrs[attr.Key] = *attr.Value.StringValue
		}
	}
	if attrs["sir.reason"] == "token "+rawToken+" should never leave the host" {
		t.Fatal("sir.reason was not sanitized")
	}
	if attrs["sir.evidence"] == `{"password":"hunter2","token":"`+rawToken+`"}` {
		t.Fatal("sir.evidence was not sanitized")
	}
	if attrs["sir.alert.diff_summary"] == "Bearer abcdef123456 leaked in diff" {
		t.Fatal("sir.alert.diff_summary was not sanitized")
	}
}

func TestLoadHealth_MissingFile(t *testing.T) {
	health, err := LoadHealth(t.TempDir())
	if err != nil {
		t.Fatalf("LoadHealth missing file: %v", err)
	}
	if health != nil {
		t.Fatalf("LoadHealth missing file = %+v, want nil", health)
	}
}

func TestRedactTarget_Secret(t *testing.T) {
	got := RedactTarget("/Users/me/.env", "secret", "read_ref")
	if !strings.HasPrefix(got, "sha256:") {
		t.Errorf("expected sha256: prefix, got %q", got)
	}
	if strings.Contains(got, ".env") {
		t.Errorf("secret path leaked: %q", got)
	}
}

func TestRedactTarget_NetworkExtractsHost(t *testing.T) {
	tests := []struct {
		in       string
		verb     string
		wantHost string
	}{
		{"https://api.example.com/v1/users?token=abc", "net_external", "api.example.com"},
		{"http://localhost:8080/health", "net_local", "localhost"},
		{"evil.com:443", "net_external", "evil.com"},
	}
	for _, tt := range tests {
		got := RedactTarget(tt.in, "", tt.verb)
		if got != tt.wantHost {
			t.Errorf("RedactTarget(%q, %q) = %q, want %q", tt.in, tt.verb, got, tt.wantHost)
		}
	}
}

func TestRedactTarget_PassthroughForFiles(t *testing.T) {
	got := RedactTarget("README.md", "", "read_ref")
	if got != "README.md" {
		t.Errorf("expected passthrough for non-secret file, got %q", got)
	}
}

func TestSeverityFromEvent(t *testing.T) {
	tests := []struct {
		ev      LogEvent
		wantNum int
		wantTxt string
	}{
		{LogEvent{Severity: "HIGH"}, 17, "ERROR"},
		{LogEvent{Severity: "MEDIUM"}, 13, "WARN"},
		{LogEvent{Verdict: "deny"}, 13, "WARN"},
		{LogEvent{Verdict: "ask"}, 9, "INFO"},
		{LogEvent{Verdict: "allow"}, 5, "DEBUG"},
	}
	for _, tt := range tests {
		num, txt := severityFromEvent(tt.ev)
		if num != tt.wantNum || txt != tt.wantTxt {
			t.Errorf("severityFromEvent(%+v) = (%d, %s), want (%d, %s)", tt.ev, num, txt, tt.wantNum, tt.wantTxt)
		}
	}
}

func TestBuildOTLPPayload_OmitsEmptyFields(t *testing.T) {
	body, err := buildOTLPPayload(LogEvent{
		ToolName: "Read",
		Verb:     "read_ref",
		Verdict:  "allow",
	}, "session-abc", "claude", "Claude Code", Version)
	if err != nil {
		t.Fatalf("buildOTLPPayload error: %v", err)
	}
	s := string(body)
	// Empty fields should not appear at all
	if strings.Contains(s, "sir.reason") {
		t.Errorf("empty reason should be omitted")
	}
	if strings.Contains(s, "sir.session.secret") {
		t.Errorf("false bool should be omitted")
	}
	// Required fields should be present
	if !strings.Contains(s, `"sir.tool_name"`) {
		t.Errorf("missing sir.tool_name attribute")
	}
}

func TestBuildOTLPPayload_IncludesEvidenceAndTamperAttrs(t *testing.T) {
	body, err := buildOTLPPayload(LogEvent{
		ToolName:     "Bash",
		Verb:         "posture_tamper",
		Verdict:      "deny",
		Evidence:     `{"result":"[REDACTED:aws_access_key]"}`,
		AlertAgentID: "gemini",
		DiffSummary:  "removed PreToolUse",
		Restored:     true,
	}, "session-abc", "claude", "Claude Code", Version)
	if err != nil {
		t.Fatalf("buildOTLPPayload error: %v", err)
	}
	s := string(body)
	for _, needle := range []string{`"sir.evidence"`, `"sir.alert.agent.id"`, `"sir.alert.diff_summary"`, `"sir.alert.restored"`} {
		if !strings.Contains(s, needle) {
			t.Fatalf("expected OTLP payload to contain %s: %s", needle, s)
		}
	}
}
