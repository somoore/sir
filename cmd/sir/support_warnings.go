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
		if line := agent.SupportManifestForAgent(s.Agent).StatusWarningLine(s.Agent.Name()); line != "" {
			fmt.Print(line)
		}
	}
}

func printDoctorSupportWarnings(statuses []agentStatus) {
	for _, s := range statuses {
		if !s.Installed || s.ReadErr != nil {
			continue
		}
		if line := agent.SupportManifestForAgent(s.Agent).DoctorWarningLine(s.Agent.Name()); line != "" {
			fmt.Print(line)
		}
	}
}
