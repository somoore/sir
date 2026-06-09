package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/telemetry"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// captureWebhook returns a test server that records every posted body.
func captureWebhook(t *testing.T) (*httptest.Server, func() []string) {
	t.Helper()
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), bodies...)
	}
}

func testEvent() telemetry.SlackEvent {
	return telemetry.SlackEvent{
		DedupKey:    "credential_in_tool_output:exfil.example@abc",
		DetectionID: "credential_in_tool_output",
		Severity:    "HIGH",
		Title:       "Credential detected in tool output",
		What:        "A credential pattern was found in tool output.",
		Why:         "Credentials in output can be forwarded off-box.",
		DataLeft:    "Detected at the boundary; redacted.",
		NextStep:    "Run sir explain --last and rotate the credential.",
		Verb:        "mcp_credential_leak",
		Target:      "exfil.example",
		LedgerIndex: 7,
		ProjectHash: "abcdef012345",
		Text:        "[sir] HIGH Credential detected in tool output",
		SuggestedActions: []telemetry.SlackAction{
			{Label: "Explain", Command: "sir explain --last"},
			{Label: "Revoke MCP server", Command: "sir mcp revoke github"},
		},
	}
}

func postEvent(t *testing.T, h http.Handler, ev telemetry.SlackEvent) {
	t.Helper()
	body, _ := json.Marshal(ev)
	req := httptest.NewRequest(http.MethodPost, "/v1/detections", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest status = %d", rec.Code)
	}
}

func TestRelay_IngestForwardsBlockKit(t *testing.T) {
	srv, bodies := captureWebhook(t)
	r, err := New(srv.URL, Options{Client: srv.Client()})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	postEvent(t, r.Handler(), testEvent())

	got := bodies()
	if len(got) != 1 {
		t.Fatalf("expected 1 forwarded message, got %d", len(got))
	}
	var msg map[string]any
	if err := json.Unmarshal([]byte(got[0]), &msg); err != nil {
		t.Fatalf("forwarded body not JSON: %v", err)
	}
	if _, ok := msg["blocks"]; !ok {
		t.Errorf("forwarded message missing blocks: %s", got[0])
	}
	// A button must carry the exact command.
	if !strings.Contains(got[0], "sir mcp revoke github") {
		t.Errorf("expected action button command in payload: %s", got[0])
	}
	if !strings.Contains(got[0], "Credential detected in tool output") {
		t.Errorf("expected title in payload: %s", got[0])
	}
}

func TestRelay_DeduplicatesWithinWindow(t *testing.T) {
	srv, bodies := captureWebhook(t)
	r, err := New(srv.URL, Options{Client: srv.Client(), DedupWindow: time.Hour})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h := r.Handler()
	postEvent(t, h, testEvent())
	postEvent(t, h, testEvent()) // same dedup_key within window -> suppressed

	if got := bodies(); len(got) != 1 {
		t.Fatalf("expected 1 forward (1 deduped), got %d", len(got))
	}
	fwd, sup := r.Stats()
	if fwd != 1 || sup != 1 {
		t.Errorf("stats forwarded=%d suppressed=%d, want 1/1", fwd, sup)
	}
}

func TestRelay_DistinctKeysBothForward(t *testing.T) {
	srv, bodies := captureWebhook(t)
	r, _ := New(srv.URL, Options{Client: srv.Client(), DedupWindow: time.Hour})
	h := r.Handler()
	postEvent(t, h, testEvent())
	ev2 := testEvent()
	ev2.DedupKey = "agent_posture_tamper:CLAUDE.md@abc"
	ev2.DetectionID = "agent_posture_tamper"
	postEvent(t, h, ev2)
	if got := bodies(); len(got) != 2 {
		t.Fatalf("distinct keys should both forward, got %d", len(got))
	}
}

// The relay replies to a button click in the HTTP response body and must never
// make an outbound request of its own — reading the attacker-controllable
// response_url to POST a reply would be a server-side request forgery. This
// test wires the relay's HTTP client to a tracking transport and asserts it is
// never used while handling an interaction.
func TestRelay_InteractionRepliesInBodyWithoutOutboundRequest(t *testing.T) {
	var outbound int
	tracking := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		outbound++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}
	r, _ := New("https://example.invalid/webhook", Options{Client: tracking})

	payload := slackInteraction{}
	payload.Actions = []struct {
		Value string `json:"value"`
	}{{Value: "sir mcp revoke github"}}
	raw, _ := json.Marshal(payload)
	form := url.Values{"payload": {string(raw)}}

	req := httptest.NewRequest(http.MethodPost, "/slack/interactions", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("interaction status = %d (should always ack)", rec.Code)
	}
	if outbound != 0 {
		t.Fatalf("SSRF: relay made %d outbound request(s) handling an interaction", outbound)
	}
	// The chosen command is echoed back in the response body (ephemeral reply).
	var reply map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatalf("interaction reply not JSON: %v", err)
	}
	if reply["response_type"] != "ephemeral" {
		t.Errorf("reply response_type = %v, want ephemeral", reply["response_type"])
	}
	if text, _ := reply["text"].(string); !strings.Contains(text, "sir mcp revoke github") {
		t.Errorf("reply body missing command: %q", text)
	}
	r.mu.Lock()
	inter := r.interactions
	r.mu.Unlock()
	if inter != 1 {
		t.Errorf("interaction counter = %d, want 1", inter)
	}
}

// An interaction with no actionable command is acked but counts for nothing.
func TestRelay_InteractionWithoutCommandIsNoop(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{})
	form := url.Values{"payload": {`{"actions":[]}`}}
	req := httptest.NewRequest(http.MethodPost, "/slack/interactions", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	r.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("interaction status = %d (should always ack)", rec.Code)
	}
	r.mu.Lock()
	inter := r.interactions
	r.mu.Unlock()
	if inter != 0 {
		t.Errorf("empty interaction should not increment the counter, got %d", inter)
	}
}

func TestRelay_DigestFlush(t *testing.T) {
	srv, bodies := captureWebhook(t)
	r, _ := New(srv.URL, Options{Client: srv.Client(), DedupWindow: time.Hour})
	h := r.Handler()
	postEvent(t, h, testEvent()) // forwarded
	postEvent(t, h, testEvent()) // suppressed but still counted in digest

	r.flushDigest()
	got := bodies()
	// 1 forward + 1 digest summary.
	if len(got) != 2 {
		t.Fatalf("expected forward + digest, got %d: %v", len(got), got)
	}
	last := got[len(got)-1]
	if !strings.Contains(last, "detection digest") || !strings.Contains(last, "credential_in_tool_output") {
		t.Errorf("digest summary malformed: %s", last)
	}
}

func TestRelay_HealthzAndBadInput(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{})
	h := r.Handler()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/detections", strings.NewReader("{not json")))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ingest = %d, want 400", rec.Code)
	}
}

func TestRelay_StatsAndAudit(t *testing.T) {
	srv, _ := captureWebhook(t)
	var logbuf bytes.Buffer
	r, _ := New(srv.URL, Options{
		Client:      srv.Client(),
		DedupWindow: time.Hour,
		Logger:      log.New(&logbuf, "", 0),
	})
	h := r.Handler()
	postEvent(t, h, testEvent())
	postEvent(t, h, testEvent()) // suppressed

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stats", nil))
	var stats map[string]int
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("stats not JSON: %v", err)
	}
	if stats["forwarded"] != 1 || stats["suppressed"] != 1 {
		t.Errorf("stats = %v, want forwarded=1 suppressed=1", stats)
	}
	// Audit log captured both the forward and the suppression, using only the
	// catalog-resolved label (never the raw request body) so log lines cannot be
	// forged through the detection ID.
	logs := logbuf.String()
	if !strings.Contains(logs, "forwarded credential_in_tool_output") {
		t.Errorf("audit log missing forward line:\n%s", logs)
	}
	if !strings.Contains(logs, "suppressed duplicate credential_in_tool_output") {
		t.Errorf("audit log missing suppression line:\n%s", logs)
	}
}

func TestRelay_RunStopsOnContextCancel(t *testing.T) {
	r, _ := New("https://example.invalid/webhook", Options{DigestEvery: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

func TestSanitizeLogValue(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"plain", "secret_to_external_egress", "secret_to_external_egress"},
		{"crlf forged line", "ok\r\nFORGED: admin login", "okFORGED: admin login"},
		{"newline only", "a\nb", "ab"},
		{"tab and bell", "a\tb\x07c", "abc"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := sanitizeLogValue(c.in); got != c.want {
				t.Errorf("sanitizeLogValue(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRelayLogfStripsInjection(t *testing.T) {
	var buf bytes.Buffer
	r, err := New("https://example.invalid/webhook", Options{Logger: log.New(&buf, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	// A string carrying CR/LF must be flattened; an int passes through verbatim.
	r.logf("forwarded %s (ledger #%d)", "bad\r\ninjected", 7)
	out := buf.String()
	if strings.ContainsAny(out, "\r") || strings.Count(out, "\n") != 1 {
		t.Errorf("logf left line breaks from a string arg: %q", out)
	}
	if !strings.Contains(out, "ledger #7") {
		t.Errorf("logf dropped a non-string arg: %q", out)
	}
}
