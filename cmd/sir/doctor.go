package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func cmdDoctor(projectRoot string) {
	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		fatal("load managed policy: %v", err)
	}
	l, err := loadLeaseForDoctor(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	fmt.Println("sir doctor")
	fmt.Println()
	if policy != nil {
		fmt.Printf("  %s\n", managedPolicyNotice(policy))
		fmt.Println("  Local baseline refresh is disabled under managed mode.")
		fmt.Println()
	}

	state, err := session.Load(projectRoot)
	if err != nil {
		if policy != nil {
			if restoreErr := restoreManagedLease(projectRoot, policy); restoreErr != nil {
				fatal("restore managed lease: %v", restoreErr)
			}
			if restored, restoreErr := restoreManagedHooks(); restoreErr != nil {
				fatal("restore managed hooks: %v", restoreErr)
			} else {
				for _, f := range restored {
					fmt.Printf("  [x] Restored: %s from managed policy\n", f.DisplayPath)
				}
			}
		}
		fmt.Println("  No active session found. Initializing fresh session.")
		state, err = hooks.SessionStart(projectRoot, l)
		if err != nil {
			fatal("session start: %v", err)
		}
		printDoctorMCPStatus(discoverMCPInventory(projectRoot))
		printDoctorOperability(projectRoot, state, 0, nil)
		fmt.Println()
		fmt.Println("sir doctor — recovery complete")
		fmt.Println()
		fmt.Println("  Session initialized.")
		fmt.Println()
		fmt.Println("sir is operational. Type 'claude' to resume.")
		_ = state
		return
	}

	fixed := false
	wasDenyAll := state.DenyAll

	if state.DenyAll {
		fmt.Printf("  [x] Cleared: session deny-all (%s)\n", state.DenyAllReason)
		state.DenyAll = false
		state.DenyAllReason = ""
		fixed = true
	}

	newLeaseHash, hashErr := posture.HashLease(projectRoot)
	if policy != nil && (hashErr != nil || state.LeaseHash != newLeaseHash) {
		if restoreErr := restoreManagedLease(projectRoot, policy); restoreErr != nil {
			fmt.Printf("  [ ] Failed: restore managed lease: %v\n", restoreErr)
		} else {
			fmt.Printf("  [x] Restored: lease.json from managed policy %s\n", policy.PolicyVersion)
			state.LeaseHash = policy.ManagedLeaseHash
			fixed = true
			l = policy.ManagedLease
		}
	} else if hashErr == nil && state.LeaseHash != newLeaseHash {
		if policy != nil {
			// managed mode handled above
		} else if wasDenyAll {
			stateDir := session.StateDir(projectRoot)
			leasePath := filepath.Join(stateDir, "lease.json")
			currentLease, leaseErr := lease.Load(leasePath)
			if leaseErr == nil {
				fmt.Println()
				fmt.Println("  WARNING: The lease has changed while deny-all was active.")
				fmt.Printf("  Current approved_hosts:   %v\n", currentLease.ApprovedHosts)
				fmt.Printf("  Current approved_remotes: %v\n", currentLease.ApprovedRemotes)
				fmt.Println()
				fmt.Print("  Accept this as the new baseline? [y/N] ")
				var confirm string
				fmt.Scanln(&confirm)
				confirm = strings.TrimSpace(strings.ToLower(confirm))
				if confirm == "y" || confirm == "yes" {
					fmt.Println("  [x] Refreshed: lease.json hash (confirmed by developer)")
					state.LeaseHash = newLeaseHash
					fixed = true
				} else {
					fmt.Println("  [ ] Skipped: lease.json hash NOT refreshed. Investigate the change before proceeding.")
				}
			} else {
				fmt.Println("  WARNING: lease hash mismatch and deny-all active, but lease could not be read.")
				fmt.Println("  [ ] Skipped: lease.json hash NOT refreshed. Run `sir install` to reset.")
			}
		} else {
			fmt.Println("  [x] Refreshed: lease.json hash")
			state.LeaseHash = newLeaseHash
			fixed = true
		}
	}

	newGlobalHash, globalHashErr := posture.HashGlobalHooks(projectRoot)
	globalHookDrift := state.GlobalHookHash != "" && ((globalHashErr == nil && state.GlobalHookHash != newGlobalHash) || os.IsNotExist(globalHashErr))
	if globalHookDrift {
		fmt.Println("  WARNING: an agent hook configuration file has changed since session start.")
		homeDir := mustHomeDir()
		restored := false
		changed, detectErr := posture.DetectChangedGlobalHooksStrict()
		if detectErr != nil {
			fatal("inspect managed hook baselines: %v", detectErr)
		}
		for _, ag := range agent.All() {
			if !ag.DetectInstallation() {
				continue
			}
			if policy != nil {
				if _, ok := policy.HookSubtree(string(ag.ID())); !ok {
					continue
				}
			} else {
				canonicalPath := ag.GetSpec().ConfigStrategy.CanonicalBackupPath(homeDir)
				if _, statErr := os.Stat(canonicalPath); statErr != nil {
					continue
				}
				fmt.Printf("  Canonical copy for %s available at %s\n", ag.Name(), canonicalPath)
				fmt.Printf("  Restore %s from canonical copy? [y/N] ", ag.ConfigPath())
				var confirm string
				fmt.Scanln(&confirm)
				confirm = strings.TrimSpace(strings.ToLower(confirm))
				if confirm != "y" && confirm != "yes" {
					fmt.Printf("  [ ] Skipped: %s NOT restored.\n", ag.ConfigPath())
					continue
				}
			}
			f := hooks.NewAgentHookFile(ag, homeDir)
			if len(changed) > 0 {
				found := false
				for _, cf := range changed {
					if cf.RelativePath == f.RelativePath {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}
			if posture.AutoRestoreAgentHookFile(f) {
				if policy != nil {
					fmt.Printf("  [x] Restored: %s hooks subtree from managed policy\n", ag.ConfigPath())
				} else {
					fmt.Printf("  [x] Restored: %s hooks subtree from canonical copy\n", ag.ConfigPath())
				}
				restored = true
			} else {
				fmt.Printf("  Failed to restore: %s\n", ag.ConfigPath())
			}
		}
		if restored {
			if rehash, rehashErr := posture.HashGlobalHooks(projectRoot); rehashErr == nil {
				state.GlobalHookHash = rehash
			}
			fixed = true
		}
		if !restored {
			if policy != nil {
				fmt.Println("  No managed hook restore was needed.")
			} else {
				fmt.Println("  No canonical copy found (or none accepted). Run 'sir install' to re-establish baseline.")
			}
		}
	}

	statuses := collectAgentStatus()
	_, schemaFixed := printDoctorAgentChecks(statuses)
	fixed = fixed || schemaFixed

	printDoctorMCPStatus(discoverMCPInventory(projectRoot))
	runtimeInspection, runtimeErr := inspectRuntimeContainment(projectRoot)
	if runtimeErr != nil {
		fmt.Printf("  WARNING: runtime containment inspection failed: %v\n", runtimeErr)
	} else if runtimeInspection != nil && runtimeInspection.Health == session.RuntimeContainmentStale {
		beforeReason := runtimeInspection.Reason
		if err := session.PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
			fmt.Printf("  WARNING: stale runtime containment cleanup failed: %v\n", err)
		} else if refreshed, err := inspectRuntimeContainment(projectRoot); err != nil {
			fmt.Printf("  WARNING: runtime containment re-check failed: %v\n", err)
		} else if refreshed == nil {
			fmt.Printf("  [x] Cleared: stale runtime containment (%s)\n", beforeReason)
			fixed = true
			runtimeInspection = nil
		} else {
			runtimeInspection = refreshed
		}
	}
	ledgerCount, ledgerErr := ledger.Verify(projectRoot)
	if ledgerErr != nil {
		fmt.Printf("  WARNING: ledger verification failed: %v\n", ledgerErr)
	}
	printDoctorOperability(projectRoot, state, ledgerCount, runtimeInspection)

	tampered := posture.CheckPostureIntegrity(projectRoot, state, l)
	if len(tampered) > 0 {
		fmt.Printf("  WARNING: %d posture file(s) modified:\n", len(tampered))
		for _, f := range tampered {
			fmt.Printf("    - %s\n", f)
		}

		newHashes := posture.HashSentinelFiles(projectRoot, l.PostureFiles)
		state.PostureHashes = newHashes
		fixed = true
	}

	saveErr := session.Update(projectRoot, func(st *session.State) error {
		if !state.DenyAll && wasDenyAll {
			st.DenyAll = false
			st.DenyAllReason = ""
		}
		if state.LeaseHash != "" {
			st.LeaseHash = state.LeaseHash
		}
		if state.GlobalHookHash != "" {
			st.GlobalHookHash = state.GlobalHookHash
		}
		if len(tampered) > 0 {
			st.PostureHashes = state.PostureHashes
		}
		return nil
	})
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save session: %v\n", saveErr)
	}

	fmt.Println()
	if fixed {
		fmt.Println("sir doctor — recovery complete")
		fmt.Println()
		fmt.Println("sir is operational. Type 'claude' to resume.")
	} else {
		fmt.Println("sir doctor — all clear")
		fmt.Println()
		fmt.Println("  Hook configuration: intact")
		fmt.Println("  Lease integrity:    verified")
		fmt.Println("  Session state:      normal")
		fmt.Println()
		fmt.Println("Nothing to fix.")
	}
}

func loadLeaseForDoctor(projectRoot string) (*lease.Lease, error) {
	if policy, err := loadManagedPolicyForCLI(); err != nil {
		return nil, err
	} else if policy != nil {
		return policy.CloneLease()
	}
	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")
	l, err := lease.Load(leasePath)
	if err != nil {
		return lease.DefaultLease(), nil
	}
	return l, nil
}
