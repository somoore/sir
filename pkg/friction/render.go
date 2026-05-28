package friction

import (
	"fmt"
	"io"
)

// Render writes a human-readable friction summary to w. It is intentionally
// quiet when there is nothing to report: a clean ledger prints a short
// "no friction" line rather than empty sections.
func Render(w io.Writer, r Report) {
	mode := "enforcement"
	if r.ObserveOnly {
		mode = "observe-only"
	}
	fmt.Fprintf(w, "sir friction — %s rollout\n", mode)
	fmt.Fprintf(w, "  sessions analyzed : %d\n", r.Sessions)
	fmt.Fprintf(w, "  decisions         : %d (%d allowed, %d prompted, %d blocked, %d alerts)\n",
		r.Decisions, r.Allowed, r.Prompts, r.Denies, r.Alerts)
	fmt.Fprintf(w, "  prompts/session   : %.2f\n", r.PromptsPerSession)
	fmt.Fprintf(w, "  blocks/session    : %.2f\n", r.DeniesPerSession)
	fmt.Fprintf(w, "  repeated prompts  : %d\n", r.RepeatedPrompts)
	fmt.Fprintf(w, "  unlocks           : %d\n", r.Unlocks)
	fmt.Fprintf(w, "  trust changes     : %d (allow-host: %d added, %d uses)\n",
		r.TrustChanges, r.AllowHostChanges, r.AllowHostUses)
	fmt.Fprintf(w, "  bypass signals    : %d unlocks, %d uninstalls\n", r.Unlocks, r.Uninstalls)
	fmt.Fprintf(w, "  slack escalations : %d\n", r.SlackEscalations)
	if r.LatencyP50Ms > 0 {
		fmt.Fprintf(w, "  decision latency  : p50 %dms, p95 %dms\n", r.LatencyP50Ms, r.LatencyP95Ms)
	}

	renderSLOs(w, r.SLOs)

	if r.Prompts == 0 && r.Denies == 0 && r.Alerts == 0 {
		fmt.Fprintln(w, "\n  No prompts or blocks recorded — sir is running quiet.")
		return
	}

	renderCounts(w, "Noisiest rules (verb)", r.NoisyRules)
	renderCounts(w, "Top blocked/asked hosts", r.TopHosts)
	renderCounts(w, "Top MCP servers (friction)", r.TopMCPServers)
	renderCounts(w, "Detections", r.Detections)
	renderCounts(w, "Likely false-positive sources (repeated intents)", r.LikelyFalsePositives)

	if len(r.Suggestions) > 0 {
		fmt.Fprintln(w, "\n  Suggested scoped leases:")
		for _, s := range r.Suggestions {
			fmt.Fprintf(w, "    • %s\n      %s\n", s.Command, s.Reason)
		}
	}
}

func renderSLOs(w io.Writer, slos []SLO) {
	if len(slos) == 0 {
		return
	}
	fmt.Fprintln(w, "\n  Service levels (lower is better):")
	for _, s := range slos {
		status := "OK"
		if !s.OK {
			status = "OVER"
		}
		fmt.Fprintf(w, "    [%-4s] %-26s %.2f (target %.2f)\n", status, s.Name, s.Value, s.Target)
	}
}

func renderCounts(w io.Writer, title string, counts []Count) {
	if len(counts) == 0 {
		return
	}
	fmt.Fprintf(w, "\n  %s:\n", title)
	for _, c := range counts {
		fmt.Fprintf(w, "    %4d  %s\n", c.N, c.Key)
	}
}
