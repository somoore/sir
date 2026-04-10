package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func inspectRuntimeContainment(projectRoot string) (*session.RuntimeContainmentInspection, error) {
	return session.InspectRuntimeContainment(projectRoot, time.Now())
}

func loadRuntimeSessionState(projectRoot string, inspection *session.RuntimeContainmentInspection) (*session.State, string, error) {
	stateDir := session.StateDir(projectRoot)
	if inspection == nil || inspection.Info == nil || inspection.Info.ShadowStateHome == "" {
		state, err := session.Load(projectRoot)
		return state, stateDir, err
	}
	if inspection.Health != session.RuntimeContainmentActive &&
		inspection.Health != session.RuntimeContainmentDegraded &&
		inspection.Health != session.RuntimeContainmentLegacy {
		state, err := session.Load(projectRoot)
		return state, stateDir, err
	}
	state, err := session.LoadFromHome(inspection.Info.ShadowStateHome, projectRoot)
	if err != nil {
		return nil, stateDir, err
	}
	return state, session.StateDirUnder(inspection.Info.ShadowStateHome, projectRoot), nil
}

func printRuntimeContainmentStatus(inspection *session.RuntimeContainmentInspection) {
	if inspection == nil || inspection.Info == nil {
		fmt.Printf("  %-9s none\n", "runtime")
		return
	}

	info := inspection.Info
	switch inspection.Health {
	case session.RuntimeContainmentActive:
		fmt.Printf("  %-9s active (%s via %s)\n", "runtime", info.AgentID, info.Mode)
		printRuntimeContainmentDetails(info)
	case session.RuntimeContainmentDegraded:
		fmt.Printf("  %-9s degraded (%s via %s)\n", "runtime", info.AgentID, info.Mode)
		printRuntimeContainmentDetails(info)
		if inspection.Reason != "" {
			fmt.Printf("             Reason: %s\n", inspection.Reason)
		}
		if warning := runtimeContainmentWarning(inspection); warning != "" {
			fmt.Printf("             Warning: %s\n", warning)
		}
		if impact := runtimeContainmentImpact(inspection); impact != "" {
			fmt.Printf("             Impact: %s\n", impact)
		}
		for _, fix := range runtimeContainmentFixes(inspection) {
			fmt.Printf("             Fix: %s\n", fix)
		}
	case session.RuntimeContainmentLegacy:
		fmt.Printf("  %-9s legacy (%s via %s)\n", "runtime", info.AgentID, info.Mode)
		printRuntimeContainmentDetails(info)
		if inspection.Reason != "" {
			fmt.Printf("             Reason: %s\n", inspection.Reason)
		}
		if warning := runtimeContainmentWarning(inspection); warning != "" {
			fmt.Printf("             Warning: %s\n", warning)
		}
		if impact := runtimeContainmentImpact(inspection); impact != "" {
			fmt.Printf("             Impact: %s\n", impact)
		}
		for _, fix := range runtimeContainmentFixes(inspection) {
			fmt.Printf("             Fix: %s\n", fix)
		}
	case session.RuntimeContainmentStale:
		fmt.Printf("  %-9s stale (%s via %s)\n", "runtime", info.AgentID, info.Mode)
		if inspection.Reason != "" {
			fmt.Printf("             Reason: %s\n", inspection.Reason)
		}
		if warning := runtimeContainmentWarning(inspection); warning != "" {
			fmt.Printf("             Warning: %s\n", warning)
		}
		if impact := runtimeContainmentImpact(inspection); impact != "" {
			fmt.Printf("             Impact: %s\n", impact)
		}
		for _, fix := range runtimeContainmentFixes(inspection) {
			fmt.Printf("             Fix: %s\n", fix)
		}
	default:
		fmt.Printf("  %-9s none\n", "runtime")
	}
}

func printRuntimeContainmentDetails(info *session.RuntimeContainment) {
	if info == nil {
		return
	}
	if protocols := info.EffectiveProxyProtocols(); len(protocols) > 0 {
		fmt.Printf("             Proxy surface: %s\n", strings.Join(protocols, ", "))
	}
	if len(info.AllowedHosts) > 0 {
		fmt.Printf("             Egress allowlist: %s\n", strings.Join(info.AllowedHosts, ", "))
	}
	if len(info.AllowedDestinations) > 0 {
		fmt.Printf("             Exact destinations: %s\n", strings.Join(info.AllowedDestinations, ", "))
	}
	if len(info.MaskedHostSockets) > 0 {
		fmt.Printf("             Masked host sockets: %s\n", strings.Join(info.MaskedHostSockets, ", "))
	}
	if len(info.ScrubbedEnvVars) > 0 {
		fmt.Printf("             Scrubbed host-control env: %s\n", strings.Join(info.ScrubbedEnvVars, ", "))
	}
}
