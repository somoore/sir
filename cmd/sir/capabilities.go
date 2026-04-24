package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/agent"
)

type capabilitiesReport struct {
	Agents []capabilityAgent `json:"agents"`
}

type capabilityAgent struct {
	ID                 agent.AgentID          `json:"id"`
	Name               string                 `json:"name"`
	Installed          bool                   `json:"installed"`
	HooksFound         int                    `json:"hooks_found"`
	HooksTotal         int                    `json:"hooks_total"`
	MissingHooks       []string               `json:"missing_hooks,omitempty"`
	SupportTier        agent.SupportTier      `json:"support_tier"`
	ToolCoverage       agent.ToolCoverage     `json:"tool_coverage"`
	SupportedEvents    []string               `json:"supported_events"`
	UnsupportedEvents  []string               `json:"unsupported_events,omitempty"`
	RequiredFlag       string                 `json:"required_feature_flag,omitempty"`
	RequiredFlagStatus string                 `json:"required_feature_flag_status,omitempty"`
	Surfaces           []agent.SupportSurface `json:"surfaces"`
}

func cmdCapabilities(args []string) {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fatal("usage: sir capabilities [--json]")
	}
	report := buildCapabilitiesReport()
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal("encode capabilities: %v", err)
		}
		return
	}
	renderCapabilitiesReport(report)
}

func buildCapabilitiesReport() capabilitiesReport {
	statuses := collectAgentStatus()
	byID := make(map[agent.AgentID]agentStatus, len(statuses))
	for _, status := range statuses {
		byID[status.Agent.ID()] = status
	}

	agents := make([]capabilityAgent, 0, len(statuses))
	for _, manifest := range agent.PublicSupportManifests() {
		status, ok := byID[manifest.ID]
		row := capabilityAgent{
			ID:                manifest.ID,
			Name:              manifest.Name,
			SupportTier:       manifest.SupportTier,
			ToolCoverage:      manifest.ToolCoverage,
			SupportedEvents:   manifest.SupportedSIREvents,
			UnsupportedEvents: manifest.UnsupportedSIREvents,
			RequiredFlag:      manifest.RequiredFeatureFlag,
			Surfaces:          manifest.Surfaces,
		}
		if ok {
			row.Installed = status.Installed
			row.HooksFound = status.Found
			row.HooksTotal = status.Total
			row.MissingHooks = append([]string(nil), status.Missing...)
			if _, featureStatus, supported := featureFlagStatusForAgent(status.Agent); supported {
				row.RequiredFlagStatus = codexFlagStatusString(featureStatus)
			}
		}
		agents = append(agents, row)
	}
	return capabilitiesReport{Agents: agents}
}

func renderCapabilitiesReport(report capabilitiesReport) {
	fmt.Println("sir capabilities")
	fmt.Println()
	for _, row := range report.Agents {
		install := "not detected"
		if row.Installed {
			install = fmt.Sprintf("%d/%d hooks registered", row.HooksFound, row.HooksTotal)
		}
		fmt.Printf("  %s  %s, %s, %s\n", row.Name, row.SupportTier, row.ToolCoverage, install)
		if row.RequiredFlag != "" {
			status := row.RequiredFlagStatus
			if status == "" {
				status = "unknown"
			}
			fmt.Printf("      feature flag: %s (%s)\n", row.RequiredFlag, status)
		}
		if len(row.MissingHooks) > 0 {
			fmt.Printf("      missing installed hooks: %s\n", strings.Join(row.MissingHooks, ", "))
		}
		if len(row.UnsupportedEvents) > 0 {
			fmt.Printf("      unsupported events: %s\n", strings.Join(row.UnsupportedEvents, ", "))
		}
		var supported []string
		for _, surface := range row.Surfaces {
			if surface.Supported {
				supported = append(supported, string(surface.Key))
			}
		}
		if len(supported) > 0 {
			fmt.Printf("      supported surfaces: %s\n", strings.Join(supported, ", "))
		}
	}
}

func codexFlagStatusString(status codexFlagStatus) string {
	switch status {
	case codexFlagAlreadyEnabled:
		return "enabled"
	case codexFlagNeedsEnable:
		return "needs_enable"
	case codexFlagMissingFile:
		return "missing_config"
	case codexFlagUnreadable:
		return "unreadable"
	default:
		return "unknown"
	}
}
