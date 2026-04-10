package main

import (
	"fmt"

	"github.com/somoore/sir/pkg/agent"
)

func printStatusSupportWarnings(statuses []agentStatus) {
	for _, s := range statuses {
		if !s.Installed || s.ReadErr != nil {
			continue
		}
		manifest := agent.SupportManifestForAgent(s.Agent)
		switch manifest.SupportTier {
		case agent.SupportTierNearParity:
			fmt.Printf("             Note: %s is near-parity support; lifecycle coverage remains narrower than Claude Code.\n", s.Agent.Name())
		case agent.SupportTierLimited:
			fmt.Printf("             Warning: %s remains limited support; enforcement is bounded by the upstream Bash-only hook surface.\n", s.Agent.Name())
		}
	}
}

func printDoctorSupportWarnings(statuses []agentStatus) {
	for _, s := range statuses {
		if !s.Installed || s.ReadErr != nil {
			continue
		}
		manifest := agent.SupportManifestForAgent(s.Agent)
		switch manifest.SupportTier {
		case agent.SupportTierNearParity:
			fmt.Printf("  NOTE: %s is near-parity support — file IFC, shell classification, MCP scanning, and credential output scanning are covered, but some lifecycle hooks remain unavailable.\n", s.Agent.Name())
		case agent.SupportTierLimited:
			fmt.Printf("  WARNING: %s is limited support — Bash-mediated actions are guarded, but native writes and MCP tools still depend on sentinel hashing plus end-of-session sweeps.\n", s.Agent.Name())
		}
	}
}
