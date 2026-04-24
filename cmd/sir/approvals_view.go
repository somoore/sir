package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

type approvalsReport struct {
	ApprovalGrants     []session.ApprovalGrant     `json:"approval_grants,omitempty"`
	LastAsk            *ledger.Entry               `json:"last_ask,omitempty"`
	ApprovedHosts      []string                    `json:"approved_hosts,omitempty"`
	ApprovedRemotes    []string                    `json:"approved_remotes,omitempty"`
	ApprovedMCPServers []string                    `json:"approved_mcp_servers,omitempty"`
	DiscoveredMCP      []lease.MCPDiscoveredServer `json:"discovered_mcp_servers,omitempty"`
	TrustedMCPServers  []string                    `json:"trusted_mcp_servers,omitempty"`
}

func cmdApprovals(projectRoot string, args []string) {
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fatal("usage: sir approvals [--json]")
	}
	report := buildApprovalsReport(projectRoot)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fatal("encode approvals: %v", err)
		}
		return
	}
	renderApprovalsReport(report)
}

func buildApprovalsReport(projectRoot string) approvalsReport {
	report := approvalsReport{}
	if state, err := session.Load(projectRoot); err == nil {
		report.ApprovalGrants = append([]session.ApprovalGrant(nil), state.ApprovalGrants...)
	}
	if entries, err := ledger.ReadAll(projectRoot); err == nil {
		for i := len(entries) - 1; i >= 0; i-- {
			if entries[i].Decision == "ask" {
				entry := entries[i]
				report.LastAsk = &entry
				break
			}
		}
	}
	l, err := loadProjectLease(projectRoot)
	if err != nil {
		l = lease.DefaultLease()
	}
	report.ApprovedHosts = append([]string(nil), l.ActiveApprovedHosts()...)
	report.ApprovedRemotes = append([]string(nil), l.ApprovedRemotes...)
	report.ApprovedMCPServers = append([]string(nil), l.ApprovedMCPServers...)
	report.DiscoveredMCP = append([]lease.MCPDiscoveredServer(nil), l.DiscoveredMCPServers...)
	report.TrustedMCPServers = append([]string(nil), l.TrustedMCPServers...)
	return report
}

func renderApprovalsReport(report approvalsReport) {
	fmt.Println("sir approvals")
	fmt.Println()
	if report.LastAsk != nil {
		fmt.Printf("  last ask:       #%d %s %s\n", report.LastAsk.Index, report.LastAsk.Verb, report.LastAsk.Target)
		fmt.Printf("                  approve retry: sir approve --last\n")
	} else {
		fmt.Println("  last ask:       none")
	}
	if len(report.ApprovalGrants) == 0 {
		fmt.Println("  retry grants:   none")
	} else {
		fmt.Printf("  retry grants:   %d\n", len(report.ApprovalGrants))
		for _, grant := range report.ApprovalGrants {
			target := grant.Target
			if strings.Contains(target, string(os.PathSeparator)) {
				target = filepath.Base(target)
			}
			fmt.Printf("    - %s %s (%s)\n", grant.Verb, target, grant.Scope)
		}
	}
	fmt.Printf("  hosts:          %s\n", emptyList(report.ApprovedHosts))
	fmt.Printf("  remotes:        %s\n", emptyList(report.ApprovedRemotes))
	fmt.Printf("  MCP approved:   %s\n", emptyList(report.ApprovedMCPServers))
	if len(report.DiscoveredMCP) > 0 {
		names := make([]string, 0, len(report.DiscoveredMCP))
		for _, server := range report.DiscoveredMCP {
			names = append(names, server.Name)
		}
		fmt.Printf("  MCP pending:    %s\n", strings.Join(names, ", "))
		fmt.Println("                  approve: sir mcp approve <name>")
	} else {
		fmt.Println("  MCP pending:    none")
	}
	if len(report.TrustedMCPServers) > 0 {
		fmt.Printf("  MCP trusted:    %s\n", strings.Join(report.TrustedMCPServers, ", "))
	}
}

func emptyList(xs []string) string {
	if len(xs) == 0 {
		return "none"
	}
	return strings.Join(xs, ", ")
}
