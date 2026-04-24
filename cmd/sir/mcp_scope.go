package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
)

func cmdMCPScope(projectRoot string, args []string) {
	if len(args) == 0 || args[0] == "list" {
		cmdMCPScopeList(projectRoot)
		return
	}
	if args[0] == "revoke" {
		if len(args) != 2 {
			fatal("usage: sir mcp scope revoke <server>")
		}
		cmdMCPScopeRevoke(projectRoot, args[1])
		return
	}
	server := args[0]
	scope := lease.MCPCapabilityScope{Server: server}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--allow-shell":
			scope.AllowShell = true
		case "--allow-network":
			scope.AllowNetwork = true
		case "--allow-write":
			scope.AllowWrite = true
		case "--root":
			if i+1 >= len(args) {
				fatal("--root requires a path")
			}
			scope.Roots = append(scope.Roots, args[i+1])
			i++
		case "--tool":
			if i+1 >= len(args) {
				fatal("--tool requires a tool name")
			}
			scope.Tools = append(scope.Tools, args[i+1])
			i++
		default:
			fatal("unknown flag: %s", args[i])
		}
	}
	if err := ensureManagedCommandAllowed("mcp scope"); err != nil {
		fatal("%v", err)
	}
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		l.UpsertMCPCapabilityScope(scope)
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "mcp_capability_scopes",
		Decision: "allow",
		Reason:   fmt.Sprintf("scoped MCP server: %s", server),
	})
	fmt.Printf("Updated MCP scope for %q.\n", server)
}

func cmdMCPScopeList(projectRoot string) {
	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}
	if len(l.MCPCapabilityScopes) == 0 {
		fmt.Println("No MCP capability scopes configured.")
		return
	}
	scopes := append([]lease.MCPCapabilityScope(nil), l.MCPCapabilityScopes...)
	sort.Slice(scopes, func(i, j int) bool { return scopes[i].Server < scopes[j].Server })
	fmt.Println("sir mcp scope list")
	for _, scope := range scopes {
		fmt.Printf("  - %s shell=%v network=%v write=%v", scope.Server, scope.AllowShell, scope.AllowNetwork, scope.AllowWrite)
		if len(scope.Tools) > 0 {
			fmt.Printf(" tools=%s", strings.Join(scope.Tools, ","))
		}
		if len(scope.Roots) > 0 {
			fmt.Printf(" roots=%s", strings.Join(scope.Roots, ","))
		}
		fmt.Println()
	}
}

func cmdMCPScopeRevoke(projectRoot, server string) {
	if err := ensureManagedCommandAllowed("mcp scope revoke"); err != nil {
		fatal("%v", err)
	}
	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		l.RemoveMCPCapabilityScope(server)
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "mcp_capability_scopes",
		Decision: "allow",
		Reason:   fmt.Sprintf("revoked MCP scope: %s", server),
	})
	fmt.Printf("Removed MCP scope for %q.\n", server)
}
