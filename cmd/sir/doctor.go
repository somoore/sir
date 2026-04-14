package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
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
		bootstrap, bootstrapErr := doctorNoSessionBootstrap(projectRoot, policy, l)
		if bootstrapErr != nil {
			if bootstrap != nil {
				printDoctorLines(bootstrap.lines)
			}
			fatal("%v", bootstrapErr)
		}
		state = bootstrap.state
		printDoctorLines(bootstrap.lines)
		printDoctorMCPStatus(discoverMCPInventory(projectRoot))
		printDoctorOperability(projectRoot, state, 0, nil)
		binaryCheck := inspectDoctorBinaryIntegrity()
		printDoctorLines(binaryCheck.lines)
		fmt.Println()
		if binaryCheck.issue {
			fmt.Println("sir doctor — recovery complete, but attention needed")
			fmt.Println()
			fmt.Println("  Session state:      initialized")
			fmt.Printf("  Binary integrity:   %s\n", binaryCheck.summary)
			fmt.Println()
			fmt.Println("Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json.")
		} else {
			fmt.Println("sir doctor — recovery complete")
			fmt.Println()
			fmt.Println("  Session initialized.")
			fmt.Println()
			fmt.Println("sir is operational. Type 'claude' to resume.")
		}
		_ = state
		return
	}

	repair, repairedLease, repairErr := runDoctorRepairs(projectRoot, policy, l, state)
	if repairErr != nil {
		if repair != nil {
			printDoctorLines(repair.preAuditLines)
			printDoctorLines(repair.preOperability)
			printDoctorLines(repair.lateLines)
		}
		fatal("%v", repairErr)
	}
	_ = repairedLease
	fixed := repair.fixed
	printDoctorLines(repair.preAuditLines)

	statuses := collectAgentStatus()
	_, schemaFixed := printDoctorAgentChecks(statuses)
	fixed = fixed || schemaFixed

	printDoctorMCPStatus(discoverMCPInventory(projectRoot))
	printDoctorLines(repair.preOperability)
	ledgerCount, ledgerErr := ledger.Verify(projectRoot)
	if ledgerErr != nil {
		fmt.Printf("  WARNING: ledger verification failed: %v\n", ledgerErr)
	}
	printDoctorOperability(projectRoot, state, ledgerCount, repair.runtimeInspection)
	binaryCheck := inspectDoctorBinaryIntegrity()
	printDoctorLines(binaryCheck.lines)
	printDoctorLines(repair.lateLines)

	saveErr := saveDoctorState(projectRoot, state)
	if saveErr != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save session: %v\n", saveErr)
	}

	fmt.Println()
	hookStatus := "intact"
	if fixed {
		hookStatus = "repaired where needed"
	}
	hasTransientRestrictions := state.HasTransientRestrictions()
	if fixed {
		if hasTransientRestrictions || binaryCheck.issue {
			fmt.Println("sir doctor — recovery complete, but attention needed")
			fmt.Println()
			fmt.Printf("  Hook configuration: %s\n", hookStatus)
			fmt.Println("  Lease integrity:    verified")
			if binaryCheck.issue {
				fmt.Printf("  Binary integrity:   %s\n", binaryCheck.summary)
			}
			if hasTransientRestrictions {
				if state.SecretSession {
					fmt.Println("  Session state:      transient restrictions active (secret session)")
				} else {
					fmt.Println("  Session state:      transient restrictions active")
				}
			} else {
				fmt.Println("  Session state:      normal")
			}
			fmt.Println()
			if binaryCheck.issue {
				fmt.Println("Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json.")
			}
			if hasTransientRestrictions {
				fmt.Println("Run 'sir unlock' to clear transient runtime restrictions.")
			}
		} else {
			fmt.Println("sir doctor — recovery complete")
			fmt.Println()
			fmt.Println("sir is operational. Type 'claude' to resume.")
		}
	} else if hasTransientRestrictions || binaryCheck.issue {
		fmt.Println("sir doctor — attention needed")
		fmt.Println()
		fmt.Printf("  Hook configuration: %s\n", hookStatus)
		fmt.Println("  Lease integrity:    verified")
		if binaryCheck.issue {
			fmt.Printf("  Binary integrity:   %s\n", binaryCheck.summary)
		}
		if hasTransientRestrictions {
			if state.SecretSession {
				fmt.Println("  Session state:      transient restrictions active (secret session)")
			} else {
				fmt.Println("  Session state:      transient restrictions active")
			}
		} else {
			fmt.Println("  Session state:      normal")
		}
		fmt.Println()
		if binaryCheck.issue {
			fmt.Println("Run 'sir verify' for full hash details, then reinstall sir to refresh ~/.sir/binary-manifest.json.")
		}
		if hasTransientRestrictions {
			fmt.Println("Run 'sir unlock' to clear transient runtime restrictions.")
		}
	} else {
		fmt.Println("sir doctor — all clear")
		fmt.Println()
		fmt.Printf("  Hook configuration: %s\n", hookStatus)
		fmt.Println("  Lease integrity:    verified")
		fmt.Println("  Session state:      normal")
		fmt.Println()
		fmt.Println("Nothing to fix.")
	}
}

type doctorBinaryIntegrityCheck struct {
	issue   bool
	summary string
	lines   []string
}

func inspectDoctorBinaryIntegrity() doctorBinaryIntegrityCheck {
	status, err := inspectBinaryIntegrity()
	if err != nil {
		return doctorBinaryIntegrityCheck{
			issue:   true,
			summary: "manifest error",
			lines: []string{
				fmt.Sprintf("  WARNING: binary integrity manifest could not be loaded: %v", err),
			},
		}
	}
	if status == nil {
		return doctorBinaryIntegrityCheck{}
	}
	if status.allOK() {
		return doctorBinaryIntegrityCheck{}
	}

	lines := []string{"  WARNING: binary integrity check failed:"}
	if status.sirErr != nil {
		lines = append(lines, fmt.Sprintf("    - sir: could not read %s: %v", status.sirPath, status.sirErr))
	} else if status.sirHash != status.manifest.SirSHA256 {
		lines = append(lines, fmt.Sprintf("    - sir: manifest %s, disk %s", shortHash(status.manifest.SirSHA256), shortHash(status.sirHash)))
	}
	if status.misterCoreErr != nil {
		lines = append(lines, fmt.Sprintf("    - mister-core: could not read %s: %v", status.misterCorePath, status.misterCoreErr))
	} else if status.misterCoreHash != status.manifest.MisterCoreSHA256 {
		lines = append(lines, fmt.Sprintf("    - mister-core: manifest %s, disk %s", shortHash(status.manifest.MisterCoreSHA256), shortHash(status.misterCoreHash)))
	}
	return doctorBinaryIntegrityCheck{
		issue:   true,
		summary: "mismatch",
		lines:   lines,
	}
}

func shortHash(h string) string {
	if len(h) > 16 {
		return h[:16] + "..."
	}
	return h
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
