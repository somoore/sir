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

func cmdStatus(projectRoot string) {
	stateDir := session.StateDir(projectRoot)
	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		fatal("load managed policy: %v", err)
	}

	statuses := collectAgentStatus()
	installed := anySirHooksRegistered(statuses)
	mcpReport := discoverMCPInventory(projectRoot)
	runtimeInspection, runtimeErr := inspectRuntimeContainment(projectRoot)
	activeStateDir := stateDir

	sep := "----------------------------------------------"

	if !installed {
		fmt.Println(sep)
		fmt.Println("  install  NOT INSTALLED")
		fmt.Println(sep)
		printMCPStatus(mcpReport)
		fmt.Println("  Run 'sir install' to set up protection.")
		return
	}

	fmt.Println(sep)
	fmt.Println("  Agents:")
	for _, s := range statuses {
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
	printStatusSupportWarnings(statuses)
	fmt.Println()

	printMCPStatus(mcpReport)

	// Load lease
	leasePath := filepath.Join(stateDir, "lease.json")
	l, err := lease.Load(leasePath)
	if policy != nil {
		l = policy.ManagedLease
		fmt.Printf("  %-9s active (%s via %s)\n", "managed", policy.PolicyVersion, policy.ManagedPolicySourcePath())
	} else if err != nil {
		l = lease.DefaultLease()
		fmt.Printf("  %-9s %s (defaults — no lease file found)\n", "mode", l.Mode)
	} else {
		fmt.Printf("  %-9s %s\n", "mode", l.Mode)
	}
	if policy != nil && l != nil {
		fmt.Printf("  %-9s %s (managed policy)\n", "mode", l.Mode)
	}

	// Check session
	var state *session.State
	var sessionErr error
	state, activeStateDir, sessionErr = loadRuntimeSessionState(projectRoot, runtimeInspection)
	if sessionErr == nil {
		shortID := state.SessionID
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		fmt.Printf("  %-9s %s (started %s)\n", "session", shortID, state.StartedAt.Format("15:04:05"))
		if state.DenyAll {
			fmt.Printf("  %-9s EMERGENCY — all tool calls blocked\n", "deny-all")
			fmt.Printf("             Reason: %s\n", state.DenyAllReason)
			fmt.Printf("             Fix:    sir doctor\n")
		} else if state.SecretSession {
			sinceFmt := state.SecretSessionSince.Format("15:04:05")
			fmt.Printf("  %-9s ACTIVE — external egress blocked since %s\n", "secrets", sinceFmt)
			fmt.Printf("             Run 'sir unlock' to restore network access.\n")
		} else {
			fmt.Printf("  %-9s none (network access unrestricted)\n", "secrets")
		}
	} else {
		fmt.Printf("  %-9s none\n", "session")
		fmt.Printf("  %-9s none\n", "secrets")
	}
	if runtimeErr != nil {
		fmt.Printf("  %-9s error: %v\n", "runtime", runtimeErr)
	} else {
		printRuntimeContainmentStatus(runtimeInspection)
	}

	// Check ledger
	count, verifyErr := ledger.Verify(projectRoot)
	operability := inspectOperability(projectRoot, state, count)
	if verifyErr != nil {
		fmt.Printf("  %-9s %d entries  CHAIN BROKEN: %v (%s)\n", "ledger", count, verifyErr, formatBytes(operability.LedgerSize))
	} else {
		fmt.Printf("  %-9s %d entries  chain valid (%s)\n", "ledger", count, formatBytes(operability.LedgerSize))
	}
	if operability.LedgerWarn {
		fmt.Printf("             Warning: ledger growth crossed the operability budget.\n")
		fmt.Printf("             Fix: archive the project state if explain/status starts to feel slow.\n")
	}
	printStatusOperability(operability)

	fmt.Printf("  %-9s %s\n", "lease", leasePath)
	fmt.Printf("  %-9s %s\n", "state", activeStateDir)
	if runtimeErr == nil && runtimeInspection != nil && runtimeInspection.Info != nil {
		fmt.Printf("  %-9s %s\n", "shadow", runtimeInspection.Info.ShadowStateHome)
	}

	fmt.Println(sep)
	fmt.Println("  Run 'sir why' to see the last decision.")
	if sessionErr == nil && state.SecretSession {
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
