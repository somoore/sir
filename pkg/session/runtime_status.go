package session

import (
	"fmt"
	"sort"
	"strings"
)

// LoadStateForRuntimeInspection loads the active session state, preferring the
// runtime shadow state when the inspection describes an active/degraded/legacy
// contained launch.
func LoadStateForRuntimeInspection(projectRoot string, inspection *RuntimeContainmentInspection) (*State, string, error) {
	stateDir := StateDir(projectRoot)
	if inspection == nil || inspection.Info == nil || inspection.Info.ShadowStateHome == "" {
		state, err := Load(projectRoot)
		return state, stateDir, err
	}
	if inspection.Health != RuntimeContainmentActive &&
		inspection.Health != RuntimeContainmentDegraded &&
		inspection.Health != RuntimeContainmentLegacy {
		state, err := Load(projectRoot)
		return state, stateDir, err
	}
	state, err := LoadFromHome(inspection.Info.ShadowStateHome, projectRoot)
	if err != nil {
		return nil, stateDir, err
	}
	return state, StateDirUnder(inspection.Info.ShadowStateHome, projectRoot), nil
}

// Warning returns the operator-facing warning for the inspection state.
func (i *RuntimeContainmentInspection) Warning() string {
	if i == nil || i.Info == nil {
		return ""
	}
	info := i.Info
	switch i.Health {
	case RuntimeContainmentDegraded:
		switch {
		case info.Mode == "darwin_local_proxy":
			return "below-hook containment is still partly proxy-shaped on this launch path"
		case len(info.MaskedHostSockets) > 0 || len(info.ScrubbedEnvVars) > 0:
			return "launch inherited host-control bridges that sir had to mask or scrub"
		default:
			return "runtime containment is active, but weaker than the target deny-by-default boundary"
		}
	case RuntimeContainmentLegacy:
		return "runtime descriptor predates heartbeat tracking and richer degradation reporting"
	case RuntimeContainmentStale:
		return "no active runtime boundary is currently protecting this session"
	default:
		return ""
	}
}

// Impact returns the concrete containment impact for the inspection state.
func (i *RuntimeContainmentInspection) Impact() string {
	if i == nil || i.Info == nil {
		return ""
	}
	info := i.Info
	switch i.Health {
	case RuntimeContainmentDegraded:
		switch {
		case info.Mode == "darwin_local_proxy":
			return "direct non-proxy sockets remain outside the exact-destination boundary on this platform"
		case len(info.MaskedHostSockets) > 0 || len(info.ScrubbedEnvVars) > 0:
			return "host control channels were present at launch; relaunch from a cleaner environment for the strongest boundary"
		default:
			return "containment guarantees are reduced until the session is relaunched cleanly"
		}
	case RuntimeContainmentLegacy:
		return "sir cannot prove the runtime boundary is still live without relaunching"
	case RuntimeContainmentStale:
		return "agent execution is no longer tied to a live containment descriptor"
	default:
		return ""
	}
}

// Fixes returns the operator-facing remediation steps for the inspection state.
func (i *RuntimeContainmentInspection) Fixes() []string {
	if i == nil || i.Info == nil {
		return nil
	}
	info := i.Info
	fixes := make([]string, 0, 5)
	switch i.Health {
	case RuntimeContainmentLegacy:
		fixes = append(fixes, "restart `sir run <agent>` to enable heartbeat-based liveness")
	case RuntimeContainmentStale:
		fixes = append(fixes,
			fmt.Sprintf("rerun `sir run %s` to rebuild the host boundary", info.AgentID),
			"run `sir doctor` once if you need to prune stale runtime state before relaunching",
		)
	case RuntimeContainmentDegraded:
		if info.Mode == "darwin_local_proxy" {
			fixes = append(fixes, "prefer Linux exact-destination containment for the strongest below-hook boundary")
		}
		if len(info.ScrubbedEnvVars) > 0 {
			fixes = append(fixes, fmt.Sprintf("relaunch from a minimal env, for example: %s", info.MinimalEnvCommand()))
		}
		if len(info.MaskedHostSockets) > 0 {
			fixes = append(fixes, fmt.Sprintf("close or avoid forwarding host-control bridges before launch: %s", info.SocketTargets()))
		}
	}
	return fixes
}

// MinimalEnvCommand returns a minimal relaunch command that unsets any
// scrubbed environment variables before running the agent again.
func (r *RuntimeContainment) MinimalEnvCommand() string {
	if r == nil || len(r.ScrubbedEnvVars) == 0 {
		return "sir run <agent>"
	}
	keys := append([]string(nil), r.ScrubbedEnvVars...)
	sort.Strings(keys)
	parts := make([]string, 0, len(keys)+3)
	parts = append(parts, "env")
	for _, key := range keys {
		parts = append(parts, "-u", key)
	}
	agentID := strings.TrimSpace(r.AgentID)
	if agentID == "" {
		agentID = "<agent>"
	}
	parts = append(parts, "sir", "run", agentID)
	return strings.Join(parts, " ")
}

// SocketTargets collapses masked socket paths into a stable, human-readable
// list for doctor/status output.
func (r *RuntimeContainment) SocketTargets() string {
	if r == nil || len(r.MaskedHostSockets) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.MaskedHostSockets))
	seen := map[string]struct{}{}
	for _, path := range r.MaskedHostSockets {
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
