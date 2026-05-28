package telemetry

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/somoore/sir/pkg/detect"
)

func TestShouldSlack_Routing(t *testing.T) {
	slack := []detect.ID{
		detect.AgentPostureTamper,
		detect.MCPBinaryOrConfigDrift,
		detect.MCPInjectionThenAction,
		detect.CredentialInToolOutput,
		detect.ControlPlaneIntegrityFailure,
		detect.PackageInstallPostureMutation,
	}
	for _, id := range slack {
		if !ShouldSlack(string(id)) {
			t.Errorf("%s should route to Slack", id)
		}
	}
	notSlack := []detect.ID{
		detect.SecretToExternalEgress, // SIEM by default
		detect.SecretToPushRemote,     // SIEM by default
		detect.NewMCPServerUsed,       // SIEM
		detect.RepeatedDeniedIntent,   // local, developer-facing
	}
	for _, id := range notSlack {
		if ShouldSlack(string(id)) {
			t.Errorf("%s should NOT route to Slack", id)
		}
	}
	if ShouldSlack("") || ShouldSlack("not_a_detection") {
		t.Error("empty/unknown detection IDs must not route to Slack")
	}
}

func TestSlackRelay_NoopWhenDisabled(t *testing.T) {
	r := newSlackRelay("", nil)
	// Must not panic and must not attempt a request.
	r.MaybeNotify(LogEvent{DetectionID: string(detect.AgentPostureTamper)})
	var nilRelay *SlackRelay
	nilRelay.MaybeNotify(LogEvent{})
}

func TestSlackRelay_PostsCuratedMessageForSlackRoute(t *testing.T) {
	var (
		mu   sync.Mutex
		body string
		hits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		body = string(b)
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSlackRelay(srv.URL, srv.Client())
	r.MaybeNotify(LogEvent{
		DetectionID:  string(detect.CredentialInToolOutput),
		Verb:         "mcp_credential_leak",
		Verdict:      "deny",
		AlertAgentID: "claude",
		Evidence:     "AKIAIOSFODNN7EXAMPLE secret should never be sent",
		LedgerIndex:  7,
	})

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("expected exactly 1 post, got %d", hits)
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("invalid Slack JSON: %v (%q)", err, body)
	}
	text := payload["text"]
	for _, want := range []string{"Credential detected in tool output", "What:", "Why:", "Data:", "Next:", "ledger #7"} {
		if !strings.Contains(text, want) {
			t.Errorf("curated message missing %q:\n%s", want, text)
		}
	}
	// Evidence must never reach Slack.
	if strings.Contains(text, "AKIA") {
		t.Errorf("raw evidence leaked into Slack message:\n%s", text)
	}
	// A blocked verdict must state nothing left the machine.
	if !strings.Contains(text, "no data left") {
		t.Errorf("blocked detection should state data did not leave:\n%s", text)
	}
}

func TestSlackRelay_StructuredRelayPayload(t *testing.T) {
	var (
		mu   sync.Mutex
		body string
		hits int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		mu.Lock()
		body = string(b)
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSlackRelayWithMode(srv.URL, true, srv.Client())
	r.MaybeNotify(LogEvent{
		DetectionID: string(detect.SecretToExternalEgress),
		Route:       "slack", // promoted (e.g. suspicion/repeat), so it reaches the relay
		Verb:        "net_external",
		Verdict:     "deny",
		Target:      "https://exfil.example/x",
		SessionID:   "sess-1",
		ProjectHash: "abcdef",
		LedgerIndex: 9,
		Evidence:    "AKIAIOSFODNN7EXAMPLE",
	})

	mu.Lock()
	defer mu.Unlock()
	if hits != 1 {
		t.Fatalf("expected 1 structured post, got %d", hits)
	}
	var ev SlackEvent
	if err := json.Unmarshal([]byte(body), &ev); err != nil {
		t.Fatalf("invalid structured payload: %v (%q)", err, body)
	}
	if ev.DetectionID != string(detect.SecretToExternalEgress) {
		t.Errorf("detection_id = %q", ev.DetectionID)
	}
	if ev.DedupKey == "" || !strings.Contains(ev.DedupKey, "secret_to_external_egress") {
		t.Errorf("dedup_key missing/wrong: %q", ev.DedupKey)
	}
	if ev.Target != "exfil.example" { // hostname-only, redacted
		t.Errorf("target should be hostname-only, got %q", ev.Target)
	}
	if ev.DataLeft == "" || !strings.Contains(ev.DataLeft, "no data left") {
		t.Errorf("data_left should state blocked: %q", ev.DataLeft)
	}
	// Suggested actions present and include an allow-host affordance.
	foundAllow := false
	for _, a := range ev.SuggestedActions {
		if strings.Contains(a.Command, "allow-host exfil.example") {
			foundAllow = true
		}
	}
	if !foundAllow {
		t.Errorf("expected allow-host suggested action, got %+v", ev.SuggestedActions)
	}
	// Evidence must never appear anywhere in the relay payload.
	if strings.Contains(body, "AKIA") {
		t.Errorf("raw evidence leaked into relay payload: %s", body)
	}
}

func TestSlackRelay_SilentForNonSlackRoute(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	r := newSlackRelay(srv.URL, srv.Client())
	// SIEM-routed and local-routed detections must not post to Slack.
	r.MaybeNotify(LogEvent{DetectionID: string(detect.SecretToExternalEgress), Verdict: "deny"})
	r.MaybeNotify(LogEvent{DetectionID: string(detect.RepeatedDeniedIntent), Verdict: "deny"})
	r.MaybeNotify(LogEvent{Verb: "read_ref", Verdict: "allow"}) // no detection at all
	if hits != 0 {
		t.Errorf("expected 0 Slack posts for non-Slack routes, got %d", hits)
	}
}
