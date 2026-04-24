package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
)

type replayReport struct {
	Profile       string       `json:"profile"`
	Entries       int          `json:"entries"`
	PolicyEntries int          `json:"policy_entries"`
	Changed       int          `json:"changed"`
	Stricter      int          `json:"stricter"`
	Looser        int          `json:"looser"`
	Same          int          `json:"same"`
	Changes       []replayDiff `json:"changes,omitempty"`
}

type replayDiff struct {
	Index     int    `json:"index"`
	Verb      string `json:"verb"`
	Target    string `json:"target"`
	Current   string `json:"current"`
	Projected string `json:"projected"`
	Reason    string `json:"reason"`
}

func cmdReplay(projectRoot string, args []string) {
	profile := "strict"
	asJSON := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--json":
			asJSON = true
		case "--profile":
			if i+1 >= len(args) {
				fatal("--profile requires default or strict")
			}
			profile = args[i+1]
			i++
		case "--strict":
			profile = "strict"
		case "--default", "--standard":
			profile = "default"
		default:
			fatal("usage: sir replay [--profile strict|default] [--json]")
		}
	}
	report := buildReplayReport(projectRoot, profile)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal("encode replay: %v", err)
		}
		return
	}
	renderReplayReport(report)
}

func buildReplayReport(projectRoot, profile string) replayReport {
	targetLease, err := leaseForProfile(profile)
	if err != nil {
		fatal("%v", err)
	}
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	report := replayReport{Profile: profile, Entries: len(entries)}
	for _, entry := range entries {
		current, ok := normalizeLedgerVerdict(entry.Decision)
		if !ok {
			continue
		}
		projected, reason, ok := projectEntryDecision(entry, targetLease)
		if !ok {
			continue
		}
		report.PolicyEntries++
		if projected == current {
			report.Same++
			continue
		}
		diff := replayDiff{
			Index:     entry.Index,
			Verb:      entry.Verb,
			Target:    entry.Target,
			Current:   string(current),
			Projected: string(projected),
			Reason:    reason,
		}
		report.Changes = append(report.Changes, diff)
		report.Changed++
		if verdictRank(projected) > verdictRank(current) {
			report.Stricter++
		} else {
			report.Looser++
		}
	}
	return report
}

func projectEntryDecision(entry ledger.Entry, l *lease.Lease) (policy.Verdict, string, bool) {
	verb, ok := policy.ParseVerb(entry.Verb)
	if !ok {
		return "", "", false
	}
	target := entry.Target
	if verb == policy.VerbNetAllowlisted {
		if host := hostFromTarget(target); host != "" && !l.IsApprovedHost(host) {
			return policy.VerdictDeny, "host is not approved by target profile", true
		}
	}
	if verb == policy.VerbReadRef && hooks.IsSensitivePathResolved(target, l) {
		return policy.VerdictAsk, "sensitive path read requires approval", true
	}
	if isWriteVerbForReplay(verb) && hooks.IsPostureFileResolved(target, l) {
		return policy.VerdictAsk, "posture file write requires approval", true
	}
	if l.IsVerbForbidden(verb) {
		return policy.VerdictDeny, "verb is forbidden by target profile", true
	}
	switch verb {
	case policy.VerbNetExternal, policy.VerbDnsLookup:
		return policy.VerdictDeny, "external egress is denied by default", true
	case policy.VerbPushRemote, policy.VerbNetAllowlisted:
		return policy.VerdictAsk, "destination requires approval", true
	}
	if l.IsVerbAsk(verb) {
		return policy.VerdictAsk, "verb requires approval in target profile", true
	}
	if l.IsVerbAllowed(verb) {
		return policy.VerdictAllow, "verb is allowed by target profile", true
	}
	return policy.VerdictAsk, "verb is outside the target profile allow list", true
}

func normalizeLedgerVerdict(decision string) (policy.Verdict, bool) {
	switch decision {
	case string(policy.VerdictAllow):
		return policy.VerdictAllow, true
	case string(policy.VerdictAsk):
		return policy.VerdictAsk, true
	case string(policy.VerdictDeny), "block":
		return policy.VerdictDeny, true
	default:
		return "", false
	}
}

func verdictRank(v policy.Verdict) int {
	switch v {
	case policy.VerdictAllow:
		return 0
	case policy.VerdictAsk:
		return 1
	case policy.VerdictDeny:
		return 2
	default:
		return 0
	}
}

func isWriteVerbForReplay(v policy.Verb) bool {
	return v == policy.VerbStageWrite || v == policy.VerbDeletePosture
}

func hostFromTarget(target string) string {
	target = strings.TrimSpace(target)
	if target == "" {
		return ""
	}
	if u, err := url.Parse(target); err == nil && u.Hostname() != "" {
		return strings.ToLower(u.Hostname())
	}
	if strings.Contains(target, "://") {
		return ""
	}
	if i := strings.IndexAny(target, "/:"); i >= 0 {
		target = target[:i]
	}
	return strings.ToLower(target)
}

func renderReplayReport(report replayReport) {
	fmt.Printf("sir replay --profile %s\n", report.Profile)
	fmt.Println()
	fmt.Printf("  ledger entries: %d (%d policy entries)\n", report.Entries, report.PolicyEntries)
	fmt.Printf("  same:           %d\n", report.Same)
	fmt.Printf("  changed:        %d (%d stricter, %d looser)\n", report.Changed, report.Stricter, report.Looser)
	if len(report.Changes) == 0 {
		fmt.Println()
		fmt.Println("  No decision changes projected from recorded verbs and targets.")
		return
	}
	fmt.Println()
	limit := len(report.Changes)
	if limit > 20 {
		limit = 20
	}
	for _, diff := range report.Changes[:limit] {
		fmt.Printf("  #%d %s %s: %s -> %s (%s)\n",
			diff.Index, diff.Verb, diff.Target, diff.Current, diff.Projected, diff.Reason)
	}
	if len(report.Changes) > limit {
		fmt.Printf("  ... %d more change(s). Use --json for the full projection.\n", len(report.Changes)-limit)
	}
}
