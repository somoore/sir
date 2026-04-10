package main

import (
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
)

// agentStatus is the per-agent summary reported by `sir status` / `sir doctor`.
type agentStatus struct {
	Agent       agent.Agent
	Installed   bool
	Registered  map[string]bool
	Total       int
	Found       int
	Missing     []string
	SchemaInval []string
	ReadErr     error
}

// collectAgentStatus walks every known adapter and records per-agent hook
// registration state. Adapters whose DetectInstallation returns false are
// reported as not installed but still appear in the slice so the status
// output remains deterministic.
func collectAgentStatus() []agentStatus {
	all := agent.All()
	out := make([]agentStatus, 0, len(all))
	for _, ag := range all {
		st := agentStatus{Agent: ag, Installed: ag.DetectInstallation()}
		if !st.Installed {
			out = append(out, st)
			continue
		}
		registered, err := detectRegisteredHookEventsFor(ag)
		if err != nil {
			st.ReadErr = err
			out = append(out, st)
			continue
		}
		st.Registered = registered
		events := ag.SupportedEvents()
		st.Total = len(events)
		for _, ev := range events {
			if registered[ev] {
				st.Found++
			} else {
				st.Missing = append(st.Missing, ev)
			}
		}
		if inv, _ := validateHookSchemaFor(ag); len(inv) > 0 {
			st.SchemaInval = inv
		}
		out = append(out, st)
	}
	return out
}

// anySirHooksRegistered reports whether at least one installed agent has at
// least one sir hook registered. Used by cmdStatus to preserve the legacy
// "NOT INSTALLED" top-level message.
func anySirHooksRegistered(statuses []agentStatus) bool {
	for _, s := range statuses {
		if s.Installed && s.Found > 0 {
			return true
		}
	}
	return false
}

func featureFlagStatusForAgent(ag agent.Agent) (string, codexFlagStatus, bool) {
	homeDir, _ := os.UserHomeDir()
	switch ag.ID() {
	case agent.Codex:
		configPath := filepath.Join(homeDir, ".codex", "config.toml")
		status, _, _ := codexHooksFlagStatus(configPath)
		return configPath, status, true
	default:
		return "", codexFlagUnreadable, false
	}
}
