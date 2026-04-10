package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
)

func cmdLog(projectRoot string, verify bool) {
	if verify {
		count, err := ledger.Verify(projectRoot)
		if err != nil {
			fmt.Printf("CHAIN BROKEN at entry %d: %v\n", count, err)
			os.Exit(1)
		}
		fmt.Printf("Ledger verified: %d entries, chain intact.\n", count)
		return
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	if len(entries) == 0 {
		fmt.Println("Ledger is empty.")
		return
	}

	for _, e := range entries {
		ts := e.Timestamp.Format("15:04:05")
		fmt.Printf("[%s] #%d %s %s → %s (%s)\n",
			ts, e.Index, e.Verb, e.Target, e.Decision, e.Reason)
	}
}

// ---------- sir audit ----------

func cmdAudit(projectRoot string) {
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}

	fmt.Println()
	fmt.Println(ac(auditBold, "sir audit") + " — session security summary")
	fmt.Println()

	if len(entries) == 0 {
		fmt.Println("  No events recorded.")
		fmt.Println()
		return
	}

	var allowed, asked, denied, alerts int
	for _, e := range entries {
		switch e.Decision {
		case "allow":
			allowed++
		case "ask":
			asked++
		case "deny":
			denied++
		}
		if e.AlertType != "" {
			alerts++
		}
	}

	fmt.Printf("  Events:  %s\n", ac(auditBold, fmt.Sprintf("%d total", len(entries))))
	blockedStr := ac(auditGreen, fmt.Sprintf("%d", denied))
	if denied > 0 {
		blockedStr = ac(auditBoldRed, fmt.Sprintf("%d", denied))
	}
	alertStr := ac(auditGreen, fmt.Sprintf("%d", alerts))
	if alerts > 0 {
		alertStr = ac(auditYellow, fmt.Sprintf("%d", alerts))
	}
	fmt.Printf("  Allowed: %s  |  Asked: %s  |  Blocked: %s  |  Alerts: %s\n",
		ac(auditGreen, fmt.Sprintf("%d", allowed)),
		ac(auditYellow, fmt.Sprintf("%d", asked)),
		blockedStr, alertStr,
	)
	fmt.Println()

	// Group events by category
	type categoryStats struct{ allowed, asked, denied int }
	categories := map[string]*categoryStats{
		"Network": {}, "File Access": {}, "Git": {}, "Shell": {},
		"Posture": {}, "MCP": {}, "Supply Chain": {}, "Other": {},
	}
	categorize := func(verb string) string {
		switch {
		case strings.HasPrefix(verb, "net_") || verb == "dns_lookup":
			return "Network"
		case verb == "read_ref":
			return "File Access"
		case strings.HasPrefix(verb, "push_") || verb == "commit":
			return "Git"
		case verb == "stage_write" || verb == "delete_posture":
			return "Posture"
		case strings.HasPrefix(verb, "mcp_"):
			return "MCP"
		case verb == "install_unlocked":
			return "Supply Chain"
		case verb == "execute_dry_run" || verb == "run_tests" || verb == "env_read" ||
			verb == "persistence" || verb == "sudo" || verb == "sir_self" || verb == "run_ephemeral":
			return "Shell"
		default:
			return "Other"
		}
	}
	for _, e := range entries {
		cat := categorize(e.Verb)
		cs := categories[cat]
		switch e.Decision {
		case "allow":
			cs.allowed++
		case "ask":
			cs.asked++
		case "deny":
			cs.denied++
		}
	}
	for _, catName := range []string{"Network", "File Access", "Git", "Posture", "MCP", "Supply Chain", "Shell", "Other"} {
		cs := categories[catName]
		total := cs.allowed + cs.asked + cs.denied
		if total == 0 {
			continue
		}
		header := fmt.Sprintf("── %s ", catName)
		for len(header) < 50 {
			header += "─"
		}
		fmt.Printf("  %s\n", ac(auditDim, header))
		var parts []string
		if cs.allowed > 0 {
			parts = append(parts, ac(auditGreen, fmt.Sprintf("%d allowed", cs.allowed)))
		}
		if cs.asked > 0 {
			parts = append(parts, ac(auditYellow, fmt.Sprintf("%d asked", cs.asked)))
		}
		if cs.denied > 0 {
			parts = append(parts, ac(auditBoldRed, fmt.Sprintf("%d BLOCKED", cs.denied)))
		}
		fmt.Printf("  %-10s %s\n", "", strings.Join(parts, "  |  "))
		fmt.Println()
	}

	// Recent blocks & alerts
	type notable struct {
		ts, kind, verb, target, reason string
	}
	var notables []notable
	for _, e := range entries {
		if e.Decision == "deny" {
			reason := e.Reason
			if strings.Contains(e.Verb, "net_") || strings.HasPrefix(e.Verb, "push_") {
				if causal := ledger.FindCausalSecretRead(entries, e.Index); causal != nil {
					reason = fmt.Sprintf("secret session (read %s at %s)",
						filepath.Base(causal.Target), causal.Timestamp.Format("15:04"))
				}
			}
			notables = append(notables, notable{e.Timestamp.Format("15:04"), "BLOCKED", e.Verb, e.Target, reason})
		}
		if e.AlertType != "" {
			notables = append(notables, notable{e.Timestamp.Format("15:04"), "ALERT", e.AlertType, e.Target, e.Reason})
		}
	}
	if len(notables) > 0 {
		header := "── Recent Blocks & Alerts "
		for len(header) < 50 {
			header += "─"
		}
		fmt.Printf("  %s\n", ac(auditDim, header))
		start := 0
		if len(notables) > 10 {
			start = len(notables) - 10
		}
		for _, n := range notables[start:] {
			kindColor := auditBoldRed
			if n.kind == "ALERT" {
				kindColor = auditYellow
			}
			target := n.target
			if len(target) > 50 {
				target = target[:47] + "..."
			}
			fmt.Printf("  %s  %s  %s  %s\n",
				ac(auditDim, n.ts), ac(kindColor, fmt.Sprintf("%-7s", n.kind)),
				ac(auditCyan, fmt.Sprintf("%-16s", n.verb)), target)
			if n.reason != "" {
				fmt.Printf("  %s  %s\n", strings.Repeat(" ", 7), ac(auditDim, "Why: "+n.reason))
			}
		}
		fmt.Println()
	}
}

// redactTargetIfSensitive redacts the full path of sensitive file targets in ledger output,
// showing only the filename component to avoid exposing secret paths in explain output.
func redactTargetIfSensitive(verb, target string) string {
	if verb != "read_ref" {
		return target
	}
	sensitive := []string{".env", ".pem", ".key", ".aws/", ".ssh/", "credentials", ".netrc", ".npmrc"}
	lower := strings.ToLower(target)
	for _, s := range sensitive {
		if strings.Contains(lower, s) {
			return filepath.Base(target) + " (path redacted)"
		}
	}
	return target
}
