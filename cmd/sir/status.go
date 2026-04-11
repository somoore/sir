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
	if !snapshot.installed {
		fmt.Println(statusSeparator)
		fmt.Println("  install  NOT INSTALLED")
		fmt.Println(statusSeparator)
		printMCPStatus(snapshot.mcpReport)
		fmt.Println("  Run 'sir install' to set up protection.")
		return
	}

	fmt.Println(statusSeparator)
	fmt.Println("  Agents:")
	for _, s := range snapshot.statuses {
		if !s.Installed {
			fmt.Printf("    -  %-12s not detected\n", s.Agent.Name())
			continue
		}
		if s.ReadErr != nil {
			fmt.Printf("    !  %-12s error: %v\n", s.Agent.Name(), s.ReadErr)
			continue
		}
		mark := "ok"
		if s.Found < s.Total {
			mark = "!!"
		}
		tag := agent.SupportManifestForAgent(s.Agent).StatusSuffix()
		fmt.Printf("    %-2s %-12s %d/%d hooks registered%s\n", mark, s.Agent.Name(), s.Found, s.Total, tag)
		if len(s.Missing) > 0 {
			fmt.Printf("                    Missing: %s\n", strings.Join(s.Missing, ", "))
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
		fmt.Printf("  %-9s %s (started %s)\n", "session", shortID, snapshot.state.StartedAt.Format("15:04:05"))
		if snapshot.state.DenyAll {
			fmt.Printf("  %-9s EMERGENCY — all tool calls blocked\n", "deny-all")
			fmt.Printf("             Reason: %s\n", snapshot.state.DenyAllReason)
			fmt.Printf("             Fix:    sir doctor\n")
		} else if snapshot.state.SecretSession {
			sinceFmt := snapshot.state.SecretSessionSince.Format("15:04:05")
			fmt.Printf("  %-9s ACTIVE — external egress blocked since %s\n", "secrets", sinceFmt)
			fmt.Printf("             Run 'sir unlock' to restore network access.\n")
		} else {
			fmt.Printf("  %-9s none (network access unrestricted)\n", "secrets")
		}
	} else {
		fmt.Printf("  %-9s none\n", "session")
		fmt.Printf("  %-9s none\n", "secrets")
	}
	if snapshot.runtimeErr != nil {
		fmt.Printf("  %-9s error: %v\n", "runtime", snapshot.runtimeErr)
	} else {
		printRuntimeContainmentStatus(snapshot.runtimeInspection)
	}

	if snapshot.ledgerVerifyErr != nil {
		fmt.Printf("  %-9s %d entries  CHAIN BROKEN: %v (%s)\n", "ledger", snapshot.ledgerCount, snapshot.ledgerVerifyErr, formatBytes(snapshot.operability.LedgerSize))
	} else {
		fmt.Printf("  %-9s %d entries  chain valid (%s)\n", "ledger", snapshot.ledgerCount, formatBytes(snapshot.operability.LedgerSize))
	}
	if snapshot.operability.LedgerWarn {
		fmt.Printf("             Warning: ledger growth crossed the operability budget.\n")
		fmt.Printf("             Fix: archive the project state if explain/status starts to feel slow.\n")
	}
	printStatusOperability(snapshot.operability)

	fmt.Printf("  %-9s %s\n", "lease", snapshot.leasePath)
	fmt.Printf("  %-9s %s\n", "state", snapshot.activeStateDir)
	if snapshot.runtimeErr == nil && snapshot.runtimeInspection != nil && snapshot.runtimeInspection.Info != nil {
		fmt.Printf("  %-9s %s\n", "shadow", snapshot.runtimeInspection.Info.ShadowStateHome)
	}

	fmt.Println(statusSeparator)
	fmt.Println("  Run 'sir why' to see the last decision.")
	if snapshot.sessionErr == nil && snapshot.state.SecretSession {
		fmt.Println("  Run 'sir unlock' to lift the secret-session lock.")
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
