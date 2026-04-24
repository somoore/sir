package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type postureReport struct {
	Installed           bool   `json:"installed"`
	AgentCount          int    `json:"agent_count"`
	RegisteredAgents    int    `json:"registered_agents"`
	Mode                string `json:"mode,omitempty"`
	ManagedPolicy       bool   `json:"managed_policy"`
	SecretSession       bool   `json:"secret_session"`
	DenyAll             bool   `json:"deny_all"`
	Posture             string `json:"posture,omitempty"`
	MCPServers          int    `json:"mcp_servers"`
	RawMCPServers       int    `json:"raw_mcp_servers"`
	MalformedMCPServers int    `json:"malformed_mcp_servers"`
	LedgerEntries       int    `json:"ledger_entries"`
	LedgerValid         bool   `json:"ledger_valid"`
	RuntimeMode         string `json:"runtime_mode,omitempty"`
	StateDir            string `json:"state_dir"`
}

func cmdPosture(projectRoot string, args []string) {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fatal("usage: sir posture [--json]")
	}
	snapshot, err := buildStatusSnapshot(projectRoot)
	if err != nil {
		fatal("load posture: %v", err)
	}
	report := buildPostureReport(snapshot)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal("encode posture: %v", err)
		}
		return
	}
	renderPostureReport(report)
}

func buildPostureReport(snapshot statusSnapshot) postureReport {
	report := postureReport{
		Installed:     snapshot.installed,
		AgentCount:    len(snapshot.statuses),
		ManagedPolicy: snapshot.policy != nil,
		MCPServers:    len(snapshot.mcpReport.Servers),
		LedgerEntries: snapshot.ledgerCount,
		LedgerValid:   snapshot.ledgerVerifyErr == nil,
		StateDir:      snapshot.activeStateDir,
	}
	for _, status := range snapshot.statuses {
		if status.Installed && status.Total > 0 && status.Found == status.Total {
			report.RegisteredAgents++
		}
	}
	for _, server := range snapshot.mcpReport.Servers {
		switch server.RuntimeAssessment().Mode {
		case mcpRuntimeRaw:
			report.RawMCPServers++
		}
		if server.Proxy.Malformed {
			report.MalformedMCPServers++
		}
	}
	if snapshot.leaseData != nil {
		report.Mode = snapshot.leaseData.Mode
	}
	if snapshot.state != nil {
		report.SecretSession = snapshot.state.SecretSession
		report.DenyAll = snapshot.state.DenyAll
		report.Posture = string(snapshot.state.Posture)
	}
	if snapshot.runtimeInspection != nil && snapshot.runtimeInspection.Info != nil {
		report.RuntimeMode = snapshot.runtimeInspection.Info.Mode
	}
	return report
}

func renderPostureReport(report postureReport) {
	fmt.Println("sir posture")
	fmt.Println()
	fmt.Printf("  install:       %v\n", report.Installed)
	fmt.Printf("  agents:        %d fully registered / %d known\n", report.RegisteredAgents, report.AgentCount)
	if report.Mode != "" {
		fmt.Printf("  policy mode:   %s\n", report.Mode)
	}
	fmt.Printf("  managed:       %v\n", report.ManagedPolicy)
	fmt.Printf("  secrets:       %v\n", report.SecretSession)
	fmt.Printf("  deny-all:      %v\n", report.DenyAll)
	if report.Posture != "" {
		fmt.Printf("  posture:       %s\n", report.Posture)
	}
	fmt.Printf("  MCP:           %d servers (%d raw, %d malformed wrappers)\n", report.MCPServers, report.RawMCPServers, report.MalformedMCPServers)
	fmt.Printf("  ledger:        %d entries, valid=%v\n", report.LedgerEntries, report.LedgerValid)
	if report.RuntimeMode != "" {
		fmt.Printf("  runtime:       %s\n", report.RuntimeMode)
	}
	fmt.Printf("  state:         %s\n", report.StateDir)
	fmt.Println()
	fmt.Println("  Next checks: sir capabilities, sir approvals, sir replay --profile strict")
}
