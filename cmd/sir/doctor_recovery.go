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
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

type doctorBootstrapReport struct {
	lines []string
	state *session.State
}

type doctorRepairReport struct {
	fixed             bool
	preAuditLines     []string
	preOperability    []string
	lateLines         []string
	runtimeInspection *session.RuntimeContainmentInspection
}

type doctorStepResult struct {
	lines []string
	fixed bool
}

type doctorLeaseRepairResult struct {
	step  doctorStepResult
	lease *lease.Lease
}

type doctorRuntimeRepairResult struct {
	step       doctorStepResult
	inspection *session.RuntimeContainmentInspection
}

func printDoctorLines(lines []string) {
	for _, line := range lines {
		fmt.Println(line)
	}
}

func doctorConfirm(prompt string) bool {
	fmt.Print(prompt)
	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	return confirm == "y" || confirm == "yes"
}

func doctorNoSessionBootstrap(projectRoot string, policy *session.ManagedPolicy, l *lease.Lease) (*doctorBootstrapReport, error) {
	report := &doctorBootstrapReport{}
	if policy != nil {
		if err := restoreManagedLease(projectRoot, policy); err != nil {
			return nil, fmt.Errorf("restore managed lease: %w", err)
		}
		restored, err := restoreManagedHooks()
		if err != nil {
			return nil, fmt.Errorf("restore managed hooks: %w", err)
		}
		for _, f := range restored {
			report.lines = append(report.lines, fmt.Sprintf("  [x] Restored: %s from managed policy", f.DisplayPath))
		}
	}

	report.lines = append(report.lines, "  No active session found. Initializing fresh session.")
	state, err := hooks.SessionStart(projectRoot, l)
	if err != nil {
		return nil, fmt.Errorf("session start: %w", err)
	}
	report.state = state
	return report, nil
}

func runDoctorRepairs(projectRoot string, policy *session.ManagedPolicy, l *lease.Lease, state *session.State) (*doctorRepairReport, *lease.Lease, error) {
	report := &doctorRepairReport{}
	wasDenyAll := state.DenyAll

	report.addEarly(clearDoctorDenyAll(state))

	leaseRepair := repairDoctorLeaseBaseline(projectRoot, policy, l, state, wasDenyAll)
	report.addEarly(leaseRepair.step)
	l = leaseRepair.lease

	hookRepair, err := repairDoctorGlobalHooks(projectRoot, policy, state)
	if err != nil {
		return nil, l, err
	}
	report.addEarly(hookRepair)

	runtimeRepair := repairDoctorRuntimeContainment(projectRoot)
	report.addPreOperability(runtimeRepair.step)
	report.runtimeInspection = runtimeRepair.inspection

	report.addLate(repairDoctorPostureIntegrity(projectRoot, state, l))
	return report, l, nil
}

func (r *doctorRepairReport) addEarly(step doctorStepResult) {
	r.preAuditLines = append(r.preAuditLines, step.lines...)
	r.fixed = r.fixed || step.fixed
}

func (r *doctorRepairReport) addPreOperability(step doctorStepResult) {
	r.preOperability = append(r.preOperability, step.lines...)
	r.fixed = r.fixed || step.fixed
}

func (r *doctorRepairReport) addLate(step doctorStepResult) {
	r.lateLines = append(r.lateLines, step.lines...)
	r.fixed = r.fixed || step.fixed
}

func clearDoctorDenyAll(state *session.State) doctorStepResult {
	if !state.DenyAll {
		return doctorStepResult{}
	}

	result := doctorStepResult{
		lines: []string{fmt.Sprintf("  [x] Cleared: session deny-all (%s)", state.DenyAllReason)},
		fixed: true,
	}
	state.DenyAll = false
	state.DenyAllReason = ""
	return result
}

func repairDoctorLeaseBaseline(projectRoot string, policy *session.ManagedPolicy, l *lease.Lease, state *session.State, wasDenyAll bool) doctorLeaseRepairResult {
	result := doctorLeaseRepairResult{lease: l}

	newLeaseHash, hashErr := posture.HashLease(projectRoot)
	if policy != nil && (hashErr != nil || state.LeaseHash != newLeaseHash) {
		if err := restoreManagedLease(projectRoot, policy); err != nil {
			result.step.lines = append(result.step.lines, fmt.Sprintf("  [ ] Failed: restore managed lease: %v", err))
			return result
		}
		result.step.lines = append(result.step.lines, fmt.Sprintf("  [x] Restored: lease.json from managed policy %s", policy.PolicyVersion))
		result.step.fixed = true
		state.LeaseHash = policy.ManagedLeaseHash
		result.lease = policy.ManagedLease
		return result
	}

	if hashErr != nil || state.LeaseHash == newLeaseHash {
		return result
	}

	if wasDenyAll {
		stateDir := session.StateDir(projectRoot)
		leasePath := filepath.Join(stateDir, "lease.json")
		currentLease, err := lease.Load(leasePath)
		if err != nil {
			result.step.lines = append(result.step.lines,
				"  WARNING: lease hash mismatch and deny-all active, but lease could not be read.",
				"  [ ] Skipped: lease.json hash NOT refreshed. Run `sir install` to reset.",
			)
			return result
		}

		result.step.lines = append(result.step.lines,
			"",
			"  WARNING: The lease has changed while deny-all was active.",
			fmt.Sprintf("  Current approved_hosts:   %v", currentLease.ApprovedHosts),
			fmt.Sprintf("  Current approved_remotes: %v", currentLease.ApprovedRemotes),
			"",
		)
		if doctorConfirm("  Accept this as the new baseline? [y/N] ") {
			result.step.lines = append(result.step.lines, "  [x] Refreshed: lease.json hash (confirmed by developer)")
			result.step.fixed = true
			state.LeaseHash = newLeaseHash
			return result
		}

		result.step.lines = append(result.step.lines, "  [ ] Skipped: lease.json hash NOT refreshed. Investigate the change before proceeding.")
		return result
	}

	result.step.lines = append(result.step.lines, "  [x] Refreshed: lease.json hash")
	result.step.fixed = true
	state.LeaseHash = newLeaseHash
	return result
}

func repairDoctorGlobalHooks(projectRoot string, policy *session.ManagedPolicy, state *session.State) (doctorStepResult, error) {
	newGlobalHash, globalHashErr := posture.HashGlobalHooks(projectRoot)
	globalHookDrift := state.GlobalHookHash != "" && ((globalHashErr == nil && state.GlobalHookHash != newGlobalHash) || os.IsNotExist(globalHashErr))
	if !globalHookDrift {
		return doctorStepResult{}, nil
	}

	result := doctorStepResult{
		lines: []string{"  WARNING: an agent hook configuration file has changed since session start."},
	}
	homeDir := mustHomeDir()
	restored := false

	changed, err := posture.DetectChangedGlobalHooksStrict()
	if err != nil {
		return doctorStepResult{}, fmt.Errorf("inspect managed hook baselines: %w", err)
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
			result.lines = append(result.lines, fmt.Sprintf("  Canonical copy for %s available at %s", ag.Name(), canonicalPath))
			if !doctorConfirm(fmt.Sprintf("  Restore %s from canonical copy? [y/N] ", ag.ConfigPath())) {
				result.lines = append(result.lines, fmt.Sprintf("  [ ] Skipped: %s NOT restored.", ag.ConfigPath()))
				continue
			}
		}

		f := hooks.NewAgentHookFile(ag, homeDir)
		if len(changed) > 0 && !doctorHookWasChanged(changed, f.RelativePath) {
			continue
		}

		if posture.AutoRestoreAgentHookFile(f) {
			if policy != nil {
				result.lines = append(result.lines, fmt.Sprintf("  [x] Restored: %s hooks subtree from managed policy", ag.ConfigPath()))
			} else {
				result.lines = append(result.lines, fmt.Sprintf("  [x] Restored: %s hooks subtree from canonical copy", ag.ConfigPath()))
			}
			restored = true
			continue
		}
		result.lines = append(result.lines, fmt.Sprintf("  Failed to restore: %s", ag.ConfigPath()))
	}

	if restored {
		if rehash, rehashErr := posture.HashGlobalHooks(projectRoot); rehashErr == nil {
			state.GlobalHookHash = rehash
		}
		result.fixed = true
		return result, nil
	}

	if policy != nil {
		result.lines = append(result.lines, "  No managed hook restore was needed.")
	} else {
		result.lines = append(result.lines, "  No canonical copy found (or none accepted). Run 'sir install' to re-establish baseline.")
	}
	return result, nil
}

func doctorHookWasChanged(changed []posture.AgentHookFile, relativePath string) bool {
	for _, f := range changed {
		if f.RelativePath == relativePath {
			return true
		}
	}
	return false
}

func repairDoctorRuntimeContainment(projectRoot string) doctorRuntimeRepairResult {
	result := doctorRuntimeRepairResult{}

	inspection, err := inspectRuntimeContainment(projectRoot)
	if err != nil {
		result.step.lines = append(result.step.lines, fmt.Sprintf("  WARNING: runtime containment inspection failed: %v", err))
		return result
	}
	if inspection == nil || inspection.Health != session.RuntimeContainmentStale {
		result.inspection = inspection
		return result
	}

	beforeReason := inspection.Reason
	if err := session.PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
		result.step.lines = append(result.step.lines, fmt.Sprintf("  WARNING: stale runtime containment cleanup failed: %v", err))
		result.inspection = inspection
		return result
	}

	refreshed, err := inspectRuntimeContainment(projectRoot)
	if err != nil {
		result.step.lines = append(result.step.lines, fmt.Sprintf("  WARNING: runtime containment re-check failed: %v", err))
		result.inspection = inspection
		return result
	}
	if refreshed == nil {
		result.step.lines = append(result.step.lines, fmt.Sprintf("  [x] Cleared: stale runtime containment (%s)", beforeReason))
		result.step.fixed = true
		return result
	}

	result.inspection = refreshed
	return result
}

func repairDoctorPostureIntegrity(projectRoot string, state *session.State, l *lease.Lease) doctorStepResult {
	tampered := posture.CheckPostureIntegrity(projectRoot, state, l)
	if len(tampered) == 0 {
		return doctorStepResult{}
	}

	lines := []string{fmt.Sprintf("  WARNING: %d posture file(s) modified:", len(tampered))}
	for _, f := range tampered {
		lines = append(lines, fmt.Sprintf("    - %s", f))
	}

	state.PostureHashes = posture.HashSentinelFiles(projectRoot, l.PostureFiles)
	return doctorStepResult{
		lines: lines,
		fixed: true,
	}
}

func saveDoctorState(projectRoot string, state *session.State) error {
	return session.Update(projectRoot, func(st *session.State) error {
		st.DenyAll = state.DenyAll
		st.DenyAllReason = state.DenyAllReason
		st.LeaseHash = state.LeaseHash
		st.GlobalHookHash = state.GlobalHookHash
		st.PostureHashes = state.PostureHashes
		return nil
	})
}
