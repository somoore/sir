package friction

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/detect"
	"github.com/somoore/sir/pkg/ledger"
)

func at(base time.Time, mins int) time.Time { return base.Add(time.Duration(mins) * time.Minute) }

func TestAnalyze_EmptyLedger(t *testing.T) {
	r := Analyze(nil)
	if r.Sessions != 0 || r.Decisions != 0 || r.Prompts != 0 {
		t.Fatalf("empty ledger should be all-zero, got %+v", r)
	}
}

func TestAnalyze_CountsAndPerSession(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "net_external", Target: "https://api.example.com/x", Decision: "ask", Timestamp: at(base, 1)},
		{Verb: "net_external", Target: "https://api.example.com/y", Decision: "deny", Timestamp: at(base, 2)},
		// session boundary marker
		{Verb: "session_end", Decision: "allow", Timestamp: at(base, 3)},
		{Verb: "run_tests", Decision: "allow", Timestamp: at(base, 4)},
		{Verb: "push_remote", Target: "git@evil.example:repo", Decision: "deny", Timestamp: at(base, 5)},
	}
	r := Analyze(entries)
	if r.Sessions != 2 {
		t.Errorf("sessions = %d, want 2", r.Sessions)
	}
	if r.Decisions != 5 {
		t.Errorf("decisions = %d, want 5 (markers excluded)", r.Decisions)
	}
	if r.Allowed != 2 || r.Prompts != 1 || r.Denies != 2 {
		t.Errorf("allowed=%d prompts=%d denies=%d, want 2/1/2", r.Allowed, r.Prompts, r.Denies)
	}
	if got := r.PromptsPerSession; got != 0.5 {
		t.Errorf("prompts/session = %v, want 0.5", got)
	}
	if got := r.DeniesPerSession; got != 1.0 {
		t.Errorf("denies/session = %v, want 1.0", got)
	}
}

func TestAnalyze_TimeGapSplitsSessions(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 90)}, // >30m gap
	}
	if r := Analyze(entries); r.Sessions != 2 {
		t.Errorf("sessions = %d, want 2 (time gap)", r.Sessions)
	}
}

func TestAnalyze_RepeatedAndHosts(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "net_external", Target: "https://pkg.example.com/a", Decision: "deny", Timestamp: at(base, 0)},
		{Verb: "net_external", Target: "https://pkg.example.com/b", Decision: "deny", Timestamp: at(base, 1)},
		{Verb: "net_external", Target: "https://pkg.example.com/c", Decision: "ask", Timestamp: at(base, 2)},
	}
	r := Analyze(entries)
	// Three blocks to the same host -> two repeats (after first occurrence).
	if r.RepeatedPrompts != 2 {
		t.Errorf("repeated prompts = %d, want 2", r.RepeatedPrompts)
	}
	if len(r.TopHosts) != 1 || r.TopHosts[0].Key != "pkg.example.com" || r.TopHosts[0].N != 3 {
		t.Errorf("top hosts = %+v, want pkg.example.com=3", r.TopHosts)
	}
	if len(r.NoisyRules) != 1 || r.NoisyRules[0].Key != "net_external" {
		t.Errorf("noisy rules = %+v, want net_external", r.NoisyRules)
	}
	// Should suggest a scoped TTL host lease.
	found := false
	for _, s := range r.Suggestions {
		if s.Action == "allow_host" && s.Target == "pkg.example.com" {
			found = true
			if !strings.Contains(s.Command, "--ttl") {
				t.Errorf("host suggestion not TTL-scoped: %q", s.Command)
			}
		}
	}
	if !found {
		t.Errorf("expected allow_host suggestion, got %+v", r.Suggestions)
	}
}

func TestAnalyze_MCPServerExtractionAndSuggestion(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{ToolName: "mcp__github__create_issue", Verb: "mcp_onboarding", Decision: "ask", Timestamp: at(base, 0)},
		{ToolName: "mcp__github__list_repos", Verb: "mcp_onboarding", Decision: "ask", Timestamp: at(base, 1)},
	}
	r := Analyze(entries)
	if len(r.TopMCPServers) != 1 || r.TopMCPServers[0].Key != "github" {
		t.Fatalf("top mcp servers = %+v, want github", r.TopMCPServers)
	}
	found := false
	for _, s := range r.Suggestions {
		if s.Action == "approve_mcp" && s.Target == "github" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected approve_mcp suggestion for github, got %+v", r.Suggestions)
	}
}

func TestAnalyze_MarkersTrustUnlockAllowHost(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "session_cleared", Target: "transient_restrictions", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "lease_modify", Target: "approved_hosts", Decision: "allow", Timestamp: at(base, 1)},
		{Verb: "lease_modify", Target: "trusted_mcp_servers", Decision: "allow", Timestamp: at(base, 2)},
		{Verb: "approval_grant", Decision: "allow", Timestamp: at(base, 3)},
		{Verb: "net_allowlisted", Target: "https://api.github.com", Decision: "allow", Timestamp: at(base, 4)},
	}
	r := Analyze(entries)
	if r.Unlocks != 1 {
		t.Errorf("unlocks = %d, want 1", r.Unlocks)
	}
	if r.TrustChanges != 3 {
		t.Errorf("trust changes = %d, want 3 (2 lease_modify + 1 grant)", r.TrustChanges)
	}
	if r.AllowHostChanges != 1 {
		t.Errorf("allow-host changes = %d, want 1", r.AllowHostChanges)
	}
	if r.AllowHostUses != 1 {
		t.Errorf("allow-host uses = %d, want 1", r.AllowHostUses)
	}
	// Only one real decision entry (net_allowlisted allow).
	if r.Decisions != 1 || r.Sessions != 1 {
		t.Errorf("decisions=%d sessions=%d, want 1/1", r.Decisions, r.Sessions)
	}
}

func TestAnalyze_DetectionsFromStampedAndDerived(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		// Pre-stamped detection ID survives.
		{Verb: "net_external", Decision: "deny", DetectionID: string(detect.SecretToExternalEgress), Timestamp: at(base, 0)},
		// Unstamped posture-change alert is re-derived at read time.
		{Verb: "stage_write", Decision: "deny", AlertType: "config_change_posture", Timestamp: at(base, 1)},
		// Unrestored hook tamper escalates to a control-plane failure.
		{Verb: "stage_write", Decision: "deny", AlertType: "hook_tamper", Timestamp: at(base, 2)},
		// Restored hook tamper stays an agent_posture_tamper.
		{Verb: "stage_write", Decision: "deny", AlertType: "hook_tamper", Restored: true, Timestamp: at(base, 3)},
	}
	r := Analyze(entries)
	got := map[string]int{}
	for _, c := range r.Detections {
		got[c.Key] = c.N
	}
	if got[string(detect.SecretToExternalEgress)] != 1 {
		t.Errorf("missing secret_to_external_egress detection: %+v", r.Detections)
	}
	if got[string(detect.AgentPostureTamper)] != 2 {
		t.Errorf("agent_posture_tamper = %d, want 2 (config_change + restored tamper): %+v", got[string(detect.AgentPostureTamper)], r.Detections)
	}
	if got[string(detect.ControlPlaneIntegrityFailure)] != 1 {
		t.Errorf("control_plane_integrity_failure = %d, want 1 (unrestored tamper): %+v", got[string(detect.ControlPlaneIntegrityFailure)], r.Detections)
	}
}

func TestAnalyze_ObserveOnlyDetected(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "net_external", Target: "https://x.example", Decision: "would_deny", Timestamp: at(base, 0)},
	}
	r := Analyze(entries)
	if !r.ObserveOnly {
		t.Error("expected ObserveOnly to be true for would_* decisions")
	}
	if r.Denies != 1 {
		t.Errorf("would_deny should count as a block, got denies=%d", r.Denies)
	}
}

func sloByName(r Report, name string) (SLO, bool) {
	for _, s := range r.SLOs {
		if s.Name == name {
			return s, true
		}
	}
	return SLO{}, false
}

func TestAnalyze_SLOsAndSlackEscalations(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	// One session: a posture-tamper alert (Slack-routed) plus several prompts.
	entries := []ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "stage_write", Decision: "deny", AlertType: "hook_tamper", Restored: true, Timestamp: at(base, 1)},
		{Verb: "net_external", Target: "https://x.example/a", Decision: "ask", Timestamp: at(base, 2)},
		{Verb: "net_external", Target: "https://x.example/b", Decision: "ask", Timestamp: at(base, 3)},
	}
	r := Analyze(entries)

	// agent_posture_tamper routes to Slack -> counted.
	if r.SlackEscalations != 1 {
		t.Errorf("slack escalations = %d, want 1", r.SlackEscalations)
	}
	if len(r.SLOs) == 0 {
		t.Fatal("expected SLOs to be computed")
	}
	// 2 prompts in 1 session = 2.0/session, over the 1.0 target.
	if s, ok := sloByName(r, "prompts/session"); !ok || s.OK {
		t.Errorf("prompts/session SLO should be OVER: %+v ok=%v", s, ok)
	}
	// slack escalations/session = 1.0, over the 0.10 target.
	if s, ok := sloByName(r, "slack escalations/session"); !ok || s.OK {
		t.Errorf("slack SLO should be OVER: %+v ok=%v", s, ok)
	}
}

func TestAnalyze_QuietLedgerMeetsSLOs(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	r := Analyze([]ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "run_tests", Decision: "allow", Timestamp: at(base, 1)},
	})
	for _, s := range r.SLOs {
		if !s.OK {
			t.Errorf("clean ledger SLO %q should be OK, got %.2f > %.2f", s.Name, s.Value, s.Target)
		}
	}
}

func TestAnalyze_LatencyPercentiles(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	var entries []ledger.Entry
	for i, ms := range []int{10, 20, 30, 40, 200} {
		entries = append(entries, ledger.Entry{
			Verb: "read_ref", Decision: "allow", LatencyMs: ms, Timestamp: at(base, i),
		})
	}
	r := Analyze(entries)
	if r.LatencyP50Ms != 30 {
		t.Errorf("p50 = %d, want 30", r.LatencyP50Ms)
	}
	if r.LatencyP95Ms != 200 {
		t.Errorf("p95 = %d, want 200", r.LatencyP95Ms)
	}
	// 200ms median? No — median is 30 (OK). But p95 high. The latency SLO keys
	// off p50, so it should be OK here.
	if s, ok := sloByName(r, "median latency ms"); !ok || !s.OK {
		t.Errorf("median latency SLO should be OK: %+v ok=%v", s, ok)
	}
}

func TestAnalyze_UninstallCountedAsBypass(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: at(base, 0)},
		{Verb: "session_cleared", Target: "transient_restrictions", Decision: "allow", Timestamp: at(base, 1)},
		{Verb: "sir_uninstall", Target: "all agents", Decision: "alert", Timestamp: at(base, 2)},
	}
	r := Analyze(entries)
	if r.Uninstalls != 1 {
		t.Errorf("uninstalls = %d, want 1", r.Uninstalls)
	}
	if r.Unlocks != 1 {
		t.Errorf("unlocks = %d, want 1", r.Unlocks)
	}
	// uninstall is a marker, not a decision.
	if r.Decisions != 1 {
		t.Errorf("decisions = %d, want 1 (markers excluded)", r.Decisions)
	}
	if s, ok := sloByName(r, "bypasses/session"); !ok {
		t.Errorf("expected bypasses/session SLO: ok=%v", ok)
	} else if s.Value != 2.0 {
		t.Errorf("bypasses/session value = %.2f, want 2.0 (1 unlock + 1 uninstall)", s.Value)
	}
}

func TestRender_QuietLedger(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, Analyze([]ledger.Entry{
		{Verb: "read_ref", Decision: "allow", Timestamp: time.Now()},
	}))
	out := buf.String()
	if !strings.Contains(out, "running quiet") {
		t.Errorf("expected quiet message, got:\n%s", out)
	}
}

func TestRender_WithFriction(t *testing.T) {
	base := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	var buf bytes.Buffer
	Render(&buf, Analyze([]ledger.Entry{
		{Verb: "net_external", Target: "https://pkg.example.com/a", Decision: "deny", Timestamp: at(base, 0)},
		{Verb: "net_external", Target: "https://pkg.example.com/b", Decision: "deny", Timestamp: at(base, 1)},
	}))
	out := buf.String()
	for _, want := range []string{"Noisiest rules", "pkg.example.com", "Suggested scoped leases", "sir allow-host"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q in:\n%s", want, out)
		}
	}
}
