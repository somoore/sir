// Package friction summarizes the developer-interruption cost of running sir.
//
// It reads the append-only ledger and reports how often sir prompts or
// blocks, which rules are noisiest, which hosts and MCP servers drive the
// friction, and which scoped leases would most reduce it. The same analysis
// is useful after an observe-only rollout (where blocks are recorded as
// would_* without interrupting) and after enforcement is enabled.
//
// The package is pure over its inputs: it imports only the ledger entry type
// and the detection taxonomy, so it can be unit-tested with synthetic ledgers
// and reused by both `sir friction` and `sir policy suggest`.
package friction

import (
	"sort"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/ledger"
)

// SLO targets treat developer interruption as a product service level. They
// are deliberately tight: every prompt is a small failure unless the developer
// is the only one who can safely decide.
const (
	targetPromptsPerSession  = 1.0
	targetBlocksPerSession   = 0.5
	targetRepeatedPromptRate = 0.20
	targetSlackPerSession    = 0.10
	targetUnlocksPerSession  = 0.20
	targetMedianLatencyMs    = 75.0 // sir's decision should be effectively invisible
)

// SLO is one service-level objective evaluated against observed data.
type SLO struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Target float64 `json:"target"`
	OK     bool    `json:"ok"` // true when value <= target (lower is better)
}

// sessionGap is the inactivity gap that starts a new session when no explicit
// session_end/session_summary marker is present. It is deliberately much
// larger than the 30-second turn heuristic.
const sessionGap = 30 * time.Minute

// Count is a key with an occurrence count, used for ranked top-N lists.
type Count struct {
	Key string `json:"key"`
	N   int    `json:"count"`
}

// Suggestion is a recommended, narrowly-scoped policy change derived from the
// observed friction, with the exact command to apply it.
type Suggestion struct {
	Action  string `json:"action"`  // e.g. "allow_host", "allow_remote", "approve_mcp"
	Target  string `json:"target"`  // the host/remote/server the suggestion concerns
	Command string `json:"command"` // the exact sir command to apply it
	Reason  string `json:"reason"`  // why this is suggested
	Hits    int    `json:"hits"`    // how many prompts/denies this would absorb
}

// Report is the full friction summary for a project's ledger.
type Report struct {
	Sessions          int     `json:"sessions"`
	Decisions         int     `json:"decisions"` // allow+ask+deny+alert entries
	Allowed           int     `json:"allowed"`
	Prompts           int     `json:"prompts"` // ask decisions
	Denies            int     `json:"denies"`
	Alerts            int     `json:"alerts"`
	PromptsPerSession float64 `json:"prompts_per_session"`
	DeniesPerSession  float64 `json:"denies_per_session"`
	RepeatedPrompts   int     `json:"repeated_prompts"` // ask/deny of an intent already seen this analysis
	Unlocks           int     `json:"unlocks"`
	Uninstalls        int     `json:"uninstalls"` // sir uninstall events (bypass signal)
	TrustChanges      int     `json:"trust_changes"`
	AllowHostChanges  int     `json:"allow_host_changes"` // leases added via `sir allow-host`
	AllowHostUses     int     `json:"allow_host_uses"`    // agent calls to an allowlisted host
	SlackEscalations  int     `json:"slack_escalations"`  // detections that route to Slack
	LatencyP50Ms      int     `json:"latency_p50_ms"`     // median sir decision latency
	LatencyP95Ms      int     `json:"latency_p95_ms"`     // p95 sir decision latency
	ObserveOnly       bool    `json:"observe_only"`       // ledger contains would_* records
	SLOs              []SLO   `json:"slos"`               // service levels vs targets

	NoisyRules           []Count      `json:"noisy_rules"`            // verbs by prompt+deny volume
	TopHosts             []Count      `json:"top_hosts"`              // blocked/asked external hosts
	TopMCPServers        []Count      `json:"top_mcp_servers"`        // MCP servers by prompt+deny volume
	Detections           []Count      `json:"detections"`             // detection IDs by volume
	LikelyFalsePositives []Count      `json:"likely_false_positives"` // repeated (verb→target) hotspots
	Suggestions          []Suggestion `json:"suggestions"`
}

// blocked reports whether a decision is a prompt or a block, tolerating the
// observe-mode would_ prefix.
func blocked(decision string) bool {
	switch decision {
	case "ask", "deny", "would_ask", "would_deny":
		return true
	default:
		return false
	}
}

func isAsk(decision string) bool { return decision == "ask" || decision == "would_ask" }
func isDeny(decision string) bool {
	return decision == "deny" || decision == "would_deny"
}

// isMarker reports whether a verb is a bookkeeping entry rather than a tool
// decision. Markers are excluded from decision counts but mined for unlock,
// trust, and allow-host signals.
func isMarker(verb string) bool {
	switch verb {
	case "session_summary", "session_end", "turn_advance", "compact_reinject",
		"lease_modify", "approval_grant", "session_cleared", "sir_uninstall":
		return true
	default:
		return false
	}
}

// Analyze walks the ledger entries (in append order) and produces a Report.
func Analyze(entries []ledger.Entry) Report {
	var r Report

	// Session segmentation: a new session begins at the first decision entry,
	// after a session_end/session_summary marker, or after a long inactivity
	// gap.
	var lastTime time.Time
	prevWasTerminator := true // so the first decision opens a session
	sessionOpen := false

	verbFriction := map[string]int{}
	hostFriction := map[string]int{}
	mcpFriction := map[string]int{}
	detCounts := map[string]int{}
	intentSeen := map[string]int{}
	fpHotspots := map[string]int{}
	var latencies []int

	for i := range entries {
		e := entries[i]

		if e.Verb == "session_end" || e.Verb == "session_summary" {
			prevWasTerminator = true
			continue
		}

		// Mine CLI/bookkeeping markers.
		switch e.Verb {
		case "session_cleared":
			r.Unlocks++
			continue
		case "sir_uninstall":
			r.Uninstalls++
			continue
		case "lease_modify":
			r.TrustChanges++
			if e.Target == "approved_hosts" {
				r.AllowHostChanges++
			}
			continue
		case "approval_grant":
			r.TrustChanges++
			continue
		}
		if isMarker(e.Verb) {
			continue
		}

		// This is a tool decision entry.
		gap := !lastTime.IsZero() && e.Timestamp.Sub(lastTime) > sessionGap
		if prevWasTerminator || gap || !sessionOpen {
			r.Sessions++
			sessionOpen = true
		}
		prevWasTerminator = false
		if !e.Timestamp.IsZero() {
			lastTime = e.Timestamp
		}

		r.Decisions++
		switch {
		case e.Decision == "allow" || e.Decision == "would_allow":
			r.Allowed++
		case isAsk(e.Decision):
			r.Prompts++
		case isDeny(e.Decision):
			r.Denies++
		case e.Decision == "alert":
			r.Alerts++
		}
		if strings.HasPrefix(e.Decision, "would_") {
			r.ObserveOnly = true
		}
		if e.AlertType != "" && e.Decision != "alert" {
			r.Alerts++
		}
		if e.Verb == "net_allowlisted" {
			r.AllowHostUses++
		}
		if e.LatencyMs > 0 {
			latencies = append(latencies, e.LatencyMs)
		}

		// Friction attribution is keyed on prompts and blocks only — allows
		// are the quiet path and must not show up as noise.
		if blocked(e.Decision) {
			verbFriction[e.Verb]++
			if host := hostFromTarget(e.Verb, e.Target); host != "" {
				hostFriction[host]++
			}
			if server := mcpServer(e.ToolName, e.Verb); server != "" {
				mcpFriction[server]++
			}
			intentKey := e.Verb + " → " + displayTarget(e.Verb, e.Target)
			if intentSeen[intentKey] > 0 {
				r.RepeatedPrompts++
				fpHotspots[intentKey]++
			}
			intentSeen[intentKey]++
		}

		if id := ledger.DetectionID(e); id != "" {
			detCounts[id]++
			if meta, ok := detect.Lookup(detect.ID(id)); ok && meta.BaseRoute == detect.RouteSlack {
				r.SlackEscalations++
			}
		}
	}

	if r.Sessions == 0 && r.Decisions > 0 {
		r.Sessions = 1
	}
	if r.Sessions > 0 {
		r.PromptsPerSession = ratio(r.Prompts, r.Sessions)
		r.DeniesPerSession = ratio(r.Denies, r.Sessions)
	}

	r.NoisyRules = topCounts(verbFriction, 8)
	r.TopHosts = topCounts(hostFriction, 8)
	r.TopMCPServers = topCounts(mcpFriction, 8)
	r.Detections = topCounts(detCounts, 0)
	r.LikelyFalsePositives = topCounts(fpHotspots, 8)
	r.Suggestions = buildSuggestions(hostFriction, mcpFriction, detCounts)
	r.LatencyP50Ms = percentile(latencies, 50)
	r.LatencyP95Ms = percentile(latencies, 95)
	r.SLOs = r.buildSLOs()
	return r
}

// percentile returns the p-th percentile (nearest-rank) of the values, or 0
// when there are none.
func percentile(values []int, p int) int {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	rank := (p*len(sorted) + 99) / 100 // ceil(p/100 * n)
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

// buildSLOs evaluates the friction service levels against their targets. All
// are "lower is better" rates per session.
func (r Report) buildSLOs() []SLO {
	sessions := r.Sessions
	if sessions < 1 {
		sessions = 1
	}
	per := func(n int) float64 { return float64(n) / float64(sessions) }
	repeatedRate := 0.0
	if denom := r.Prompts + r.Denies; denom > 0 {
		repeatedRate = float64(r.RepeatedPrompts) / float64(denom)
	}
	slo := func(name string, value, target float64) SLO {
		return SLO{Name: name, Value: value, Target: target, OK: value <= target+1e-9}
	}
	slos := []SLO{
		slo("prompts/session", r.PromptsPerSession, targetPromptsPerSession),
		slo("blocks/session", r.DeniesPerSession, targetBlocksPerSession),
		slo("repeated-prompt rate", repeatedRate, targetRepeatedPromptRate),
		slo("slack escalations/session", per(r.SlackEscalations), targetSlackPerSession),
		slo("bypasses/session", per(r.Unlocks+r.Uninstalls), targetUnlocksPerSession),
	}
	// Only assert the latency objective once we have measurements.
	if r.LatencyP50Ms > 0 {
		slos = append(slos, slo("median latency ms", float64(r.LatencyP50Ms), targetMedianLatencyMs))
	}
	return slos
}

func ratio(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d)
}

// topCounts returns counts sorted descending by N then key. limit<=0 returns all.
func topCounts(m map[string]int, limit int) []Count {
	out := make([]Count, 0, len(m))
	for k, n := range m {
		out = append(out, Count{Key: k, N: n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].N != out[j].N {
			return out[i].N > out[j].N
		}
		return out[i].Key < out[j].Key
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
