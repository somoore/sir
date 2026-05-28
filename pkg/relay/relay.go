// Package relay implements the central sir Slack relay: the operator-run
// service that workstations point SIR_SLACK_RELAY at. It ingests structured
// detection events, deduplicates them across the fleet, renders curated Slack
// Block Kit messages (with the suggested actions as buttons), forwards them to
// a single downstream Slack webhook, posts periodic digests, and acknowledges
// button-click interactions. Centralizing here keeps webhook secrets and
// per-event spam off individual machines.
//
// Standard library only, per the sir implementation rules.
package relay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/telemetry"
)

const (
	defaultDedupWindow   = 10 * time.Minute
	defaultDigestEvery   = time.Hour
	maxIngestBytes       = 64 * 1024
	maxInteractionBytes  = 64 * 1024
	forwardClientTimeout = 3 * time.Second
)

// Relay forwards curated detection alerts to a Slack webhook with fleet-wide
// dedup and digesting. The zero value is not usable; construct with New.
type Relay struct {
	webhook     string
	client      *http.Client
	dedupWindow time.Duration
	digestEvery time.Duration
	logger      *log.Logger

	mu           sync.Mutex
	seen         map[string]time.Time // dedup_key -> last forwarded
	digest       map[string]int       // detection_id -> count since last flush
	forwarded    int
	suppressed   int
	interactions int
}

// Options configure a Relay. Zero values fall back to defaults.
type Options struct {
	DedupWindow time.Duration
	DigestEvery time.Duration
	Client      *http.Client
	// Logger, when set, receives an audit line for every forwarded alert and
	// every button interaction. nil disables audit logging (useful in tests).
	Logger *log.Logger
}

// New constructs a Relay that forwards to the given Slack webhook URL.
func New(webhook string, opts Options) (*Relay, error) {
	webhook = strings.TrimSpace(webhook)
	if webhook == "" {
		return nil, fmt.Errorf("relay: empty Slack webhook URL")
	}
	if _, err := url.ParseRequestURI(webhook); err != nil {
		return nil, fmt.Errorf("relay: invalid Slack webhook URL: %w", err)
	}
	r := &Relay{
		webhook:     webhook,
		client:      opts.Client,
		dedupWindow: opts.DedupWindow,
		digestEvery: opts.DigestEvery,
		logger:      opts.Logger,
		seen:        make(map[string]time.Time),
		digest:      make(map[string]int),
	}
	if r.client == nil {
		r.client = &http.Client{Timeout: forwardClientTimeout}
	}
	if r.dedupWindow <= 0 {
		r.dedupWindow = defaultDedupWindow
	}
	if r.digestEvery == 0 {
		r.digestEvery = defaultDigestEvery
	}
	return r, nil
}

// Handler returns the relay's HTTP routes:
//
//	POST /v1/detections    ingest a structured SlackEvent from a workstation
//	POST /slack/interactions  acknowledge a Slack button click
//	GET  /healthz          liveness
func (r *Relay) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/detections", r.handleIngest)
	mux.HandleFunc("/slack/interactions", r.handleInteraction)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/stats", r.handleStats)
	return mux
}

func (r *Relay) handleStats(w http.ResponseWriter, _ *http.Request) {
	fwd, sup := r.Stats()
	r.mu.Lock()
	inter := r.interactions
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"forwarded": fwd, "suppressed": sup, "interactions": inter,
	})
}

func (r *Relay) logf(format string, args ...any) {
	if r.logger != nil {
		r.logger.Printf(format, args...)
	}
}

// detectionLabel resolves an incoming detection ID to a known label from the
// local taxonomy. The incoming id is only ever compared against the catalog's
// constant IDs; on a match the *catalog constant* is returned, never the
// request-supplied string. So the value written to the audit log provably
// originates from the controlled taxonomy — an attacker cannot forge log lines
// (e.g. via embedded newlines) through it.
func detectionLabel(id string) string {
	for _, known := range detect.AllIDs() {
		if string(known) == id {
			return string(known)
		}
	}
	return "unknown"
}

// Run starts the digest ticker until ctx is cancelled. Safe to skip (digesting
// is optional); ingestion works without it.
func (r *Relay) Run(ctx context.Context) {
	if r.digestEvery <= 0 {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(r.digestEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.flushDigest()
		}
	}
}

func (r *Relay) handleIngest(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxIngestBytes))
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	var ev telemetry.SlackEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "invalid event", http.StatusBadRequest)
		return
	}
	if ev.DetectionID == "" {
		http.Error(w, "missing detection_id", http.StatusBadRequest)
		return
	}
	deduped := r.ingest(ev)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"deduped": deduped})
}

// ingest records the event for digesting and forwards it to Slack unless an
// identical dedup_key was forwarded within the window. Returns true when the
// event was deduplicated (suppressed).
func (r *Relay) ingest(ev telemetry.SlackEvent) bool {
	key := ev.DedupKey
	if key == "" {
		key = ev.DetectionID
	}

	r.mu.Lock()
	r.digest[ev.DetectionID]++
	last, seen := r.seen[key]
	now := time.Now()
	if seen && now.Sub(last) < r.dedupWindow {
		r.suppressed++
		r.mu.Unlock()
		r.logf("suppressed duplicate %s (ledger #%d)", detectionLabel(ev.DetectionID), ev.LedgerIndex)
		return true
	}
	r.seen[key] = now
	r.forwarded++
	r.mu.Unlock()

	r.logf("forwarded %s (ledger #%d)", detectionLabel(ev.DetectionID), ev.LedgerIndex)
	r.forward(blockKitMessage(ev))
	return false
}

func (r *Relay) handleInteraction(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxInteractionBytes))
	if err != nil {
		w.WriteHeader(http.StatusOK) // always ack; never wedge Slack
		return
	}
	// Slack posts interactions as form-encoded with a JSON "payload" field.
	values, err := url.ParseQuery(string(body))
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	var payload slackInteraction
	if raw := values.Get("payload"); raw != "" {
		_ = json.Unmarshal([]byte(raw), &payload)
	}
	// Echo the chosen command back as an ephemeral message *in the HTTP response
	// body* — Slack renders the in-body reply, so the relay never makes an
	// outbound request to the attacker-controllable response_url (no SSRF) and
	// never executes anything on a workstation. The command is the developer's
	// to run; central lease changes flow through the managed-policy channel,
	// not here.
	cmd := payload.command()
	if cmd == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	r.mu.Lock()
	r.interactions++
	r.mu.Unlock()
	r.logf("interaction acknowledged")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"response_type": "ephemeral",
		"text":          "Run on the affected workstation:\n```" + cmd + "```",
	})
}

// flushDigest posts a summary of detections seen since the last flush, then
// resets the counters. It is a no-op when nothing was seen.
func (r *Relay) flushDigest() {
	r.mu.Lock()
	if len(r.digest) == 0 {
		r.mu.Unlock()
		return
	}
	type kv struct {
		id string
		n  int
	}
	items := make([]kv, 0, len(r.digest))
	total := 0
	for id, n := range r.digest {
		items = append(items, kv{id, n})
		total += n
	}
	suppressed := r.suppressed
	r.digest = make(map[string]int)
	r.suppressed = 0
	r.mu.Unlock()

	sort.Slice(items, func(i, j int) bool {
		if items[i].n != items[j].n {
			return items[i].n > items[j].n
		}
		return items[i].id < items[j].id
	})
	var b strings.Builder
	fmt.Fprintf(&b, "*[sir] detection digest* — %d detections", total)
	if suppressed > 0 {
		fmt.Fprintf(&b, " (%d duplicates suppressed)", suppressed)
	}
	b.WriteString("\n")
	for _, it := range items {
		fmt.Fprintf(&b, "• %s: %d\n", it.id, it.n)
	}
	r.forward(map[string]any{"text": strings.TrimRight(b.String(), "\n")})
}

func (r *Relay) forward(payload map[string]any) {
	r.forwardTo(r.webhook, payload)
}

func (r *Relay) forwardTo(endpoint string, payload map[string]any) {
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), forwardClientTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
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

// Stats returns forwarded/suppressed counters (for tests and /healthz-style
// introspection).
func (r *Relay) Stats() (forwarded, suppressed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.forwarded, r.suppressed
}
