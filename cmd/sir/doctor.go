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
			fatal("%v", bootstrapErr)
		}
		state = bootstrap.state
		printDoctorLines(bootstrap.lines)
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

	repair, repairedLease, repairErr := runDoctorRepairs(projectRoot, policy, l, state)
	if repairErr != nil {
		fatal("%v", repairErr)
	}
	l = repairedLease
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
	printDoctorLines(repair.lateLines)

	saveErr := saveDoctorState(projectRoot, state)
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
