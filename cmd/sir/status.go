package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

const statusSeparator = "----------------------------------------------"

type statusSnapshot struct {
	stateDir          string
	activeStateDir    string
	policy            *session.ManagedPolicy
	statuses          []agentStatus
	installed         bool
	mcpReport         mcpInventoryReport
	runtimeInspection *session.RuntimeContainmentInspection
	runtimeErr        error
	leasePath         string
	leaseData         *lease.Lease
	leaseErr          error
	state             *session.State
	sessionErr        error
	ledgerCount       int
	ledgerVerifyErr   error
	operability       operabilitySnapshot
}

func cmdStatus(projectRoot string) {
	snapshot, err := buildStatusSnapshot(projectRoot)
	if err != nil {
		fatal("load managed policy: %v", err)
	}
	renderStatusSnapshot(snapshot)
}

func buildStatusSnapshot(projectRoot string) (statusSnapshot, error) {
	snapshot := statusSnapshot{
		stateDir:       session.StateDir(projectRoot),
		activeStateDir: session.StateDir(projectRoot),
	}

	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		return statusSnapshot{}, err
	}
	snapshot.policy = policy
	snapshot.statuses = collectAgentStatus()
	snapshot.installed = anySirHooksRegistered(snapshot.statuses)
	snapshot.mcpReport = discoverMCPInventory(projectRoot)
	snapshot.runtimeInspection, snapshot.runtimeErr = inspectRuntimeContainment(projectRoot)

	if !snapshot.installed {
		return snapshot, nil
	}

	snapshot.leasePath = filepath.Join(snapshot.stateDir, "lease.json")
	snapshot.leaseData, snapshot.leaseErr = lease.Load(snapshot.leasePath)
	if snapshot.policy != nil {
		snapshot.leaseData = snapshot.policy.ManagedLease
		snapshot.leaseErr = nil
	} else if snapshot.leaseErr != nil {
		snapshot.leaseData = lease.DefaultLease()
	}

	snapshot.state, snapshot.activeStateDir, snapshot.sessionErr = session.LoadStateForRuntimeInspection(projectRoot, snapshot.runtimeInspection)
	snapshot.ledgerCount, snapshot.ledgerVerifyErr = ledger.Verify(projectRoot)
	snapshot.operability = inspectOperability(projectRoot, snapshot.state, snapshot.ledgerCount)
	return snapshot, nil
}

func renderStatusSnapshot(snapshot statusSnapshot) {
	sep := ac(auditDim, statusSeparator)
	if !snapshot.installed {
		fmt.Println(sep)
		fmt.Printf("  install  %s\n", ac(auditBoldRed, "NOT INSTALLED"))
		fmt.Println(sep)
		printMCPStatus(snapshot.mcpReport)
		fmt.Println(ac(auditDim, "  Run 'sir install' to set up protection."))
		return
	}

	fmt.Println(sep)
	fmt.Printf("  %s\n", ac(auditBold, "Agents:"))
	for _, s := range snapshot.statuses {
		if !s.Installed {
			fmt.Printf("    %s  %-12s %s\n", ac(auditDim, "-"), s.Agent.Name(), ac(auditDim, "not detected"))
			continue
		}
		if s.ReadErr != nil {
			fmt.Printf("    %s  %-12s error: %v\n", ac(auditBoldRed, "!"), s.Agent.Name(), s.ReadErr)
			continue
		}
		var mark string
		if s.Found < s.Total {
			mark = ac(auditYellow, "??")
		} else {
			mark = ac(auditGreen, "\u00b7 ")
		}
		tag := agent.SupportManifestForAgent(s.Agent).StatusSuffix()
		fmt.Printf("    %s %-12s %d/%d hooks registered%s\n", mark, s.Agent.Name(), s.Found, s.Total, tag)
		if len(s.Missing) > 0 {
			fmt.Printf("                    Missing: %s\n", ac(auditYellow, strings.Join(s.Missing, ", ")))
		}
	}
	printStatusSupportWarnings(snapshot.statuses)
	fmt.Println()

	printMCPStatus(snapshot.mcpReport)

	if snapshot.policy != nil {
		fmt.Printf("  %-9s active (%s via %s)\n", "managed", snapshot.policy.PolicyVersion, snapshot.policy.ManagedPolicySourcePath())
	} else if snapshot.leaseErr != nil {
		fmt.Printf("  %-9s %s (defaults — no lease file found)\n", "mode", snapshot.leaseData.Mode)
	} else {
		fmt.Printf("  %-9s %s\n", "mode", snapshot.leaseData.Mode)
	}
	if snapshot.policy != nil && snapshot.leaseData != nil {
		fmt.Printf("  %-9s %s (managed policy)\n", "mode", snapshot.leaseData.Mode)
	}

	if snapshot.sessionErr == nil {
		shortID := snapshot.state.SessionID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		fmt.Printf("  %-9s %s (started %s)\n", "session", ac(auditCyan, shortID), snapshot.state.StartedAt.Format("15:04:05"))
		if snapshot.state.DenyAll {
			fmt.Printf("  %-9s %s\n", "deny-all", ac(auditBoldRed, "EMERGENCY — all tool calls blocked"))
			fmt.Printf("             reason: %s\n", snapshot.state.DenyAllReason)
			fmt.Printf("             fix:    %s\n", ac(auditDim, "sir doctor"))
		} else if snapshot.state.SecretSession {
			sinceFmt := snapshot.state.SecretSessionSince.Format("15:04:05")
			fmt.Printf("  %-9s %s — external egress blocked since %s\n", "secrets", ac(auditBoldYellow, "ACTIVE"), sinceFmt)
			fmt.Printf("             %s\n", ac(auditDim, "Run 'sir unlock' to clear transient runtime restrictions."))
		} else {
			fmt.Printf("  %-9s %s\n", "secrets", ac(auditDim, "none (network access unrestricted)"))
		}
		if snapshot.state.Posture != "" && snapshot.state.Posture != "normal" {
			fmt.Printf("  %-9s %s\n", "posture", ac(auditYellow, string(snapshot.state.Posture)))
		}
		if len(snapshot.state.TaintedMCPServers) > 0 {
			fmt.Printf("  %-9s %s\n", "mcp taint", ac(auditYellow, strings.Join(snapshot.state.TaintedMCPServers, ", ")))
		}
		if snapshot.state.PendingInjectionAlert {
			fmt.Printf("  %-9s %s\n", "alert", ac(auditYellow, "active"))
		}
		if !snapshot.state.SecretSession && snapshot.state.HasTransientRestrictions() {
			fmt.Printf("  %-9s %s\n", "recovery", ac(auditDim, "Run 'sir unlock' to clear transient runtime restrictions."))
		}
	} else {
		fmt.Printf("  %-9s %s\n", "session", ac(auditDim, "none"))
		fmt.Printf("  %-9s %s\n", "secrets", ac(auditDim, "none"))
	}
	if snapshot.runtimeErr != nil {
		fmt.Printf("  %-9s error: %v\n", "runtime", snapshot.runtimeErr)
	} else {
		printRuntimeContainmentStatus(snapshot.runtimeInspection)
	}

	if snapshot.ledgerVerifyErr != nil {
		fmt.Printf("  %-9s %d entries  %s: %v (%s)\n", "ledger", snapshot.ledgerCount, ac(auditBoldRed, "CHAIN BROKEN"), snapshot.ledgerVerifyErr, formatBytes(snapshot.operability.LedgerSize))
	} else {
		fmt.Printf("  %-9s %d entries  %s (%s)\n", "ledger", snapshot.ledgerCount, ac(auditGreen, "chain valid"), formatBytes(snapshot.operability.LedgerSize))
	}
	if snapshot.operability.LedgerWarn {
		fmt.Printf("             %s\n", ac(auditYellow, "Warning: ledger growth crossed the operability budget."))
		fmt.Printf("             %s\n", ac(auditDim, "Fix: archive the project state if explain/status starts to feel slow."))
	}
	printStatusOperability(snapshot.operability)

	fmt.Printf("  %-9s %s\n", "lease", ac(auditDim, snapshot.leasePath))
	fmt.Printf("  %-9s %s\n", "state", ac(auditDim, snapshot.activeStateDir))
	if snapshot.runtimeErr == nil && snapshot.runtimeInspection != nil && snapshot.runtimeInspection.Info != nil {
		fmt.Printf("  %-9s %s\n", "shadow", ac(auditDim, snapshot.runtimeInspection.Info.ShadowStateHome))
	}

	fmt.Println(sep)
	fmt.Println(ac(auditDim, "  Run 'sir why' to see the last decision."))
	if snapshot.sessionErr == nil && snapshot.state.HasTransientRestrictions() {
		fmt.Println(ac(auditDim, "  Run 'sir unlock' to clear transient runtime restrictions."))
	}
}

func cmdSupport(args []string) {
	if len(args) != 1 || args[0] != "--json" {
		fatal("usage: sir support --json")
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(agent.PublicSupportManifests()); err != nil {
		fatal("encode support manifest: %v", err)
	}
}
