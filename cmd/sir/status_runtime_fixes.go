package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/session"
)

func runtimeContainmentFixes(inspection *session.RuntimeContainmentInspection) []string {
	if inspection == nil || inspection.Info == nil {
		return nil
	}
	info := inspection.Info
	fixes := make([]string, 0, 5)
	switch inspection.Health {
	case session.RuntimeContainmentLegacy:
		fixes = append(fixes, "restart `sir run <agent>` to enable heartbeat-based liveness")
	case session.RuntimeContainmentStale:
		fixes = append(fixes,
			fmt.Sprintf("rerun `sir run %s` to rebuild the host boundary", info.AgentID),
			"run `sir doctor` once if you need to prune stale runtime state before relaunching",
		)
	case session.RuntimeContainmentDegraded:
		if info.Mode == "darwin_local_proxy" {
			fixes = append(fixes, "prefer Linux exact-destination containment for the strongest below-hook boundary")
		}
		if len(info.ScrubbedEnvVars) > 0 {
			fixes = append(fixes, fmt.Sprintf("relaunch from a minimal env, for example: %s", runtimeMinimalEnvCommand(info)))
		}
		if len(info.MaskedHostSockets) > 0 {
			fixes = append(fixes, fmt.Sprintf("close or avoid forwarding host-control bridges before launch: %s", runtimeSocketTargets(info.MaskedHostSockets)))
		}
	}
	return fixes
}

func runtimeContainmentWarning(inspection *session.RuntimeContainmentInspection) string {
	if inspection == nil || inspection.Info == nil {
		return ""
	}
	info := inspection.Info
	switch inspection.Health {
	case session.RuntimeContainmentDegraded:
		switch {
		case info.Mode == "darwin_local_proxy":
			return "below-hook containment is still partly proxy-shaped on this launch path"
		case len(info.MaskedHostSockets) > 0 || len(info.ScrubbedEnvVars) > 0:
			return "launch inherited host-control bridges that sir had to mask or scrub"
		default:
			return "runtime containment is active, but weaker than the target deny-by-default boundary"
		}
	case session.RuntimeContainmentLegacy:
		return "runtime descriptor predates heartbeat tracking and richer degradation reporting"
	case session.RuntimeContainmentStale:
		return "no active runtime boundary is currently protecting this session"
	default:
		return ""
	}
}

func runtimeContainmentImpact(inspection *session.RuntimeContainmentInspection) string {
	if inspection == nil || inspection.Info == nil {
		return ""
	}
	info := inspection.Info
	switch inspection.Health {
	case session.RuntimeContainmentDegraded:
		switch {
		case info.Mode == "darwin_local_proxy":
			return "direct non-proxy sockets remain outside the exact-destination boundary on this platform"
		case len(info.MaskedHostSockets) > 0 || len(info.ScrubbedEnvVars) > 0:
			return "host control channels were present at launch; relaunch from a cleaner environment for the strongest boundary"
		default:
			return "containment guarantees are reduced until the session is relaunched cleanly"
		}
	case session.RuntimeContainmentLegacy:
		return "sir cannot prove the runtime boundary is still live without relaunching"
	case session.RuntimeContainmentStale:
		return "agent execution is no longer tied to a live containment descriptor"
	default:
		return ""
	}
}

func runtimeMinimalEnvCommand(info *session.RuntimeContainment) string {
	if info == nil || len(info.ScrubbedEnvVars) == 0 {
		return "sir run <agent>"
	}
	keys := append([]string(nil), info.ScrubbedEnvVars...)
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+3)
	parts = append(parts, "env")
	for _, key := range keys {
		parts = append(parts, "-u", key)
	}
	agentID := strings.TrimSpace(info.AgentID)
	if agentID == "" {
		agentID = "<agent>"
	}
	parts = append(parts, "sir", "run", agentID)
	return strings.Join(parts, " ")
}

func runtimeSocketTargets(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	names := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, path := range paths {
		name := strings.TrimSpace(path)
		if idx := strings.LastIndex(name, "/"); idx >= 0 {
			name = name[idx+1:]
		}
		if name == "" {
			name = path
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
