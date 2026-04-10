package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func loadManagedPolicyForCLI() (*session.ManagedPolicy, error) {
	return session.LoadManagedPolicy()
}

func managedPolicyNotice(policy *session.ManagedPolicy) string {
	if policy == nil {
		return ""
	}
	return fmt.Sprintf("managed mode active (policy %s via %s)", policy.PolicyVersion, policy.ManagedPolicySourcePath())
}

func ensureManagedCommandAllowed(command string) error {
	policy, err := loadManagedPolicyForCLI()
	if err != nil {
		return err
	}
	if policy == nil || !policy.IsLocalCommandDisabled(command) {
		return nil
	}
	return fmt.Errorf("%s is disabled by %s (policy %s). Request an admin-managed policy update instead",
		command, policy.ManagedPolicySourcePath(), policy.PolicyVersion)
}

func restoreManagedLease(projectRoot string, policy *session.ManagedPolicy) error {
	if policy == nil {
		return nil
	}
	cloned, err := policy.CloneLease()
	if err != nil {
		return err
	}
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	return cloned.Save(leasePath)
}

func restoreManagedHooks() ([]posture.AgentHookFile, error) {
	changed := posture.DetectChangedGlobalHooks()
	var restored []posture.AgentHookFile
	for _, f := range changed {
		if posture.AutoRestoreAgentHookFile(f) {
			restored = append(restored, f)
		}
	}
	return restored, nil
}

func managedCommandLabel(command string) string {
	return strings.TrimSpace(command)
}
