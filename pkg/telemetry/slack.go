package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/detect"
)

// SlackWebhookEnvVar names the environment variable holding a Slack incoming
// webhook (or a central relay endpoint that speaks the same {"text":...} JSON).
//
// The preferred production topology is a central collector: every workstation
// ships redacted detection telemetry to the SIEM via SIR_OTLP_ENDPOINT, and a
// single relay forwards the high-severity detections to Slack. That keeps
// secrets and noisy per-call telemetry off Slack and out of individual
// workstations' outbound paths. SIR_SLACK_WEBHOOK is the simpler direct path
// for individual developers who want escalations without standing up a relay.
const SlackWebhookEnvVar = "SIR_SLACK_WEBHOOK"

// ShouldSlack reports whether a detection ID warrants a Slack escalation. The
// decision is deterministic from the detection taxonomy's route: only
// detections whose route is RouteSlack (posture/binary/ledger tamper, MCP
// injection, credential exposure, control-plane failure) escalate. Repeated
// denies (RouteLocal) and routine secret-read/onboarding signals (RouteSIEM)
// never reach Slack, which is what keeps the channel actionable.
func ShouldSlack(detectionID string) bool {
	if detectionID == "" {
		return false
	}
	meta, ok := detect.Lookup(detect.ID(detectionID))
	if !ok {
		return false
	}
	return meta.BaseRoute == detect.RouteSlack
}

// eventRoutesToSlack decides whether a specific event escalates to Slack. It
// prefers the event's computed route (which includes dynamic promotion from
// suspicion or repetition) and falls back to the detection's static base route
// when the event carries no route (e.g. historical entries).
func eventRoutesToSlack(ev LogEvent) bool {
	if ev.DetectionID == "" {
		return false
	}
	if ev.Route != "" {
		return ev.Route == detect.RouteSlack.String()
	}
	return ShouldSlack(ev.DetectionID)
}

// SlackRelayEnvVar names a central relay endpoint that receives the structured
// detection event (not Slack's text format). The preferred topology is for
// every workstation to point SIR_SLACK_RELAY at one operator-run relay that
// deduplicates, routes by severity, renders interactive buttons from the
// suggested actions, and posts digests — keeping secrets and per-event spam
// off Slack and webhook URLs off individual machines.
const SlackRelayEnvVar = "SIR_SLACK_RELAY" // #nosec G101 -- env var name, not a credential

// SlackAction is a suggested next step the relay can render as an interactive
// button. Command is the exact sir command; the relay decides how to surface
// it (button, link, copy-paste).
type SlackAction struct {
	Label   string `json:"label"`
	Command string `json:"command"`
}

// SlackEvent is the structured, relay-ready detection event. It carries only
// redacted/normalized fields plus the curated narrative and suggested actions —
// never raw evidence. DedupKey lets the relay collapse repeats across a fleet.
type SlackEvent struct {
	DedupKey         string        `json:"dedup_key"`
	DetectionID      string        `json:"detection_id"`
	Severity         string        `json:"severity"`
	Title            string        `json:"title"`
	What             string        `json:"what"`
	Why              string        `json:"why"`
	DataLeft         string        `json:"data_left"`
	NextStep         string        `json:"next_step"`
	Verb             string        `json:"verb,omitempty"`
	Target           string        `json:"target,omitempty"`
	Agent            string        `json:"agent,omitempty"`
	SessionID        string        `json:"session_id,omitempty"`
	ProjectHash      string        `json:"project_hash,omitempty"`
	LedgerIndex      int           `json:"ledger_index"`
	Suspicious       bool          `json:"suspicious,omitempty"`
	Text             string        `json:"text"`
	SuggestedActions []SlackAction `json:"suggested_actions,omitempty"`
}

// SlackRelay posts curated, actionable detection alerts. With SIR_SLACK_RELAY
// it sends the structured SlackEvent to a central relay; otherwise with
// SIR_SLACK_WEBHOOK it posts the plain {"text":...} form directly to Slack.
// It is fire-and-forget and entirely opt-in: with neither set, every method is
// a no-op. It never sends raw evidence — only the curated narrative for
// high-severity detections.
type SlackRelay struct {
	endpoint   string
	structured bool
	client     *http.Client
	enabled    bool
}

// NewSlackRelay constructs a relay, preferring the central relay endpoint over
// a direct webhook. The HTTP client uses a short timeout so a slow endpoint can
// never wedge a hook; Slack escalations are rare (only RouteSlack detections)
// so a bounded synchronous post is acceptable on those infrequent events.
func NewSlackRelay() *SlackRelay {
	if relay := strings.TrimSpace(os.Getenv(SlackRelayEnvVar)); relay != "" {
		return newSlackRelayWithMode(relay, true, &http.Client{Timeout: 1500 * time.Millisecond})
	}
	return newSlackRelayWithMode(strings.TrimSpace(os.Getenv(SlackWebhookEnvVar)), false, &http.Client{Timeout: 1500 * time.Millisecond})
}

func newSlackRelay(endpoint string, client *http.Client) *SlackRelay {
	return newSlackRelayWithMode(endpoint, false, client)
}

func newSlackRelayWithMode(endpoint string, structured bool, client *http.Client) *SlackRelay {
	r := &SlackRelay{}
	if endpoint == "" {
		return r
	}
	if _, err := url.ParseRequestURI(endpoint); err != nil {
		return r
	}
	if client == nil {
		client = &http.Client{Timeout: 1500 * time.Millisecond}
	}
	r.endpoint = endpoint
	r.structured = structured
	r.client = client
	r.enabled = true
	return r
}

// MaybeNotify posts a curated alert for ev when the relay is enabled and the
// event's detection routes to Slack. It is safe on a nil receiver and never
// returns an error: a failed post must not affect enforcement.
func (r *SlackRelay) MaybeNotify(ev LogEvent) {
	if r == nil || !r.enabled {
		return
	}
	if !eventRoutesToSlack(ev) {
		return
	}
	var payload []byte
	var err error
	if r.structured {
		event, ok := BuildSlackEvent(ev)
		if !ok {
			return
		}
		payload, err = json.Marshal(event)
	} else {
		text := BuildSlackText(ev)
		if text == "" {
			return
		}
		payload, err = json.Marshal(map[string]string{"text": text})
	}
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.endpoint, bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}

// BuildSlackEvent builds the structured relay event for a detection, including
// the dedup key, curated narrative, and suggested action affordances. Returns
// ok=false for events that do not map to a known detection.
func BuildSlackEvent(ev LogEvent) (SlackEvent, bool) {
	meta, ok := detect.Lookup(detect.ID(ev.DetectionID))
	if !ok {
		return SlackEvent{}, false
	}
	target := RedactTarget(ev.Target, ev.Sensitivity, ev.Verb)
	dataLeft := meta.DataLeft
	switch ev.Verdict {
	case "deny", "would_deny":
		dataLeft = "Blocked — no data left the machine."
	}
	return SlackEvent{
		DedupKey:         slackDedupKey(ev, target),
		DetectionID:      ev.DetectionID,
		Severity:         string(meta.Severity),
		Title:            meta.Title,
		What:             meta.What,
		Why:              meta.Why,
		DataLeft:         dataLeft,
		NextStep:         meta.NextStep,
		Verb:             ev.Verb,
		Target:           target,
		Agent:            ev.AlertAgentID,
		SessionID:        ev.SessionID,
		ProjectHash:      ev.ProjectHash,
		LedgerIndex:      ev.LedgerIndex,
		Suspicious:       ev.Suspicious,
		Text:             BuildSlackText(ev),
		SuggestedActions: suggestedActions(ev, target),
	}, true
}

// slackDedupKey is a stable key the relay uses to collapse repeats of the same
// detection against the same target within a fleet/time window.
func slackDedupKey(ev LogEvent, redactedTarget string) string {
	key := ev.DetectionID
	if redactedTarget != "" {
		key += ":" + redactedTarget
	}
	if ev.ProjectHash != "" {
		key += "@" + ev.ProjectHash
	}
	return key
}

// suggestedActions derives the button-ready next steps for a detection. The
// relay renders these as interactive buttons; the commands are exact.
func suggestedActions(ev LogEvent, target string) []SlackAction {
	actions := []SlackAction{{Label: "Explain", Command: "sir explain --last"}}
	switch detect.ID(ev.DetectionID) {
	case detect.SecretToExternalEgress:
		if target != "" {
			actions = append(actions, SlackAction{Label: "Allow host 15m", Command: "sir allow-host " + target + " --ttl 15m"})
		}
	case detect.SecretToPushRemote:
		actions = append(actions, SlackAction{Label: "Allow remote", Command: "sir allow-remote <name>"})
	case detect.MCPInjectionThenAction, detect.MCPBinaryOrConfigDrift, detect.MCPChangeThenPrivilegedUse:
		if target != "" {
			actions = append(actions, SlackAction{Label: "Revoke MCP server", Command: "sir mcp revoke " + target})
		}
	case detect.AgentPostureTamper, detect.PackageInstallPostureMutation, detect.ControlPlaneIntegrityFailure:
		actions = append(actions, SlackAction{Label: "Run doctor", Command: "sir doctor"})
	}
	return actions
}

// BuildSlackText renders the curated, actionable Slack message for a detection
// event. It answers the four questions a curated alert must: what happened,
// why it mattered, whether data left the machine, and what to do next. It uses
// only redacted/normalized fields (verb, hashed-or-hostname target, ledger
// index) — never raw evidence.
func BuildSlackText(ev LogEvent) string {
	meta, ok := detect.Lookup(detect.ID(ev.DetectionID))
	if !ok {
		return ""
	}

	dataLeft := meta.DataLeft
	switch ev.Verdict {
	case "deny", "would_deny":
		dataLeft = "Blocked — no data left the machine."
	}

	agentLine := ""
	if ev.AlertAgentID != "" {
		agentLine = strings.ToUpper(ev.AlertAgentID[:1]) + ev.AlertAgentID[1:] + " "
	}
	target := RedactTarget(ev.Target, ev.Sensitivity, ev.Verb)
	where := ""
	if target != "" {
		where = fmt.Sprintf(" (%s %s)", ev.Verb, target)
	} else if ev.Verb != "" {
		where = fmt.Sprintf(" (%s)", ev.Verb)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "[sir] %s %s\n", strings.ToUpper(string(meta.Severity)), meta.Title)
	fmt.Fprintf(&b, "What: %s%s%s\n", agentLine, meta.What, where)
	fmt.Fprintf(&b, "Why: %s\n", meta.Why)
	fmt.Fprintf(&b, "Data: %s\n", dataLeft)
	fmt.Fprintf(&b, "Next: %s", meta.NextStep)
	if ev.LedgerIndex >= 0 && (ev.LedgerHash != "" || ev.LedgerIndex > 0) {
		fmt.Fprintf(&b, " (ledger #%d)", ev.LedgerIndex)
	}
	return b.String()
}
