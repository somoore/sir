package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func cmdAllowHost(projectRoot, host string) {
	if err := ensureManagedCommandAllowed("allow-host"); err != nil {
		fatal("%v", err)
	}
	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")

	l, err := lease.Load(leasePath)
	if err != nil {
		fatal("load lease: %v", err)
	}

	// Check if already approved
	for _, h := range l.ApprovedHosts {
		if h == host {
			fmt.Printf("Host %q is already in approved_hosts.\n", host)
			return
		}
	}

	// Warn and confirm
	fmt.Println()
	fmt.Printf("  WARNING: Adding %q to approved_hosts will allow sir-protected agents\n", host)
	fmt.Printf("  to make network requests to this destination without blocking.\n")
	fmt.Println()
	fmt.Printf("  Only add this host if you trust it completely.\n")
	fmt.Printf("  sir will no longer block egress to %s.\n", host)
	fmt.Println()
	fmt.Printf("  Add %q to approved_hosts? [y/N] ", host)

	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Cancelled. No changes made.")
		return
	}

	l.ApprovedHosts = append(l.ApprovedHosts, host)
	if err := l.Save(leasePath); err != nil {
		fatal("save lease: %v", err)
	}

	// Update LeaseHash in active session to prevent false-positive
	// integrity failures. session.Update holds the file lock across
	// the Load→mutate→Save sequence so concurrent CLI invocations
	// don't race — see CLAUDE.md rule 6.
	_ = session.Update(projectRoot, func(state *session.State) error {
		newHash, err := posture.HashLease(projectRoot)
		if err != nil {
			return err
		}
		state.LeaseHash = newHash
		return nil
	})

	// Log to ledger
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "approved_hosts",
		Decision: "allow",
		Reason:   fmt.Sprintf("added host: %s", host),
	})

	fmt.Printf("Added %q to approved_hosts. sir-protected agents can now reach this host.\n", host)
}

func cmdAllowRemote(projectRoot, remote string) {
	if err := ensureManagedCommandAllowed("allow-remote"); err != nil {
		fatal("%v", err)
	}
	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")

	l, err := lease.Load(leasePath)
	if err != nil {
		fatal("load lease: %v", err)
	}

	// Check if already approved
	for _, r := range l.ApprovedRemotes {
		if r == remote {
			fmt.Printf("Remote %q is already in approved_remotes.\n", remote)
			return
		}
	}

	// Warn and confirm
	fmt.Println()
	fmt.Printf("  WARNING: Adding %q to approved_remotes will allow sir-protected agents\n", remote)
	fmt.Printf("  to push code to this git remote without additional prompts.\n")
	fmt.Println()
	fmt.Printf("  Only add this remote if you trust the destination repository.\n")
	fmt.Println()
	fmt.Printf("  Add %q to approved_remotes? [y/N] ", remote)

	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Cancelled. No changes made.")
		return
	}

	l.ApprovedRemotes = append(l.ApprovedRemotes, remote)
	if err := l.Save(leasePath); err != nil {
		fatal("save lease: %v", err)
	}

	// Update LeaseHash in active session to prevent false-positive
	// integrity failures. session.Update holds the file lock across
	// the Load→mutate→Save sequence so concurrent CLI invocations
	// don't race — see CLAUDE.md rule 6.
	_ = session.Update(projectRoot, func(state *session.State) error {
		newHash, err := posture.HashLease(projectRoot)
		if err != nil {
			return err
		}
		state.LeaseHash = newHash
		return nil
	})

	// Log to ledger
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "approved_remotes",
		Decision: "allow",
		Reason:   fmt.Sprintf("added remote: %s", remote),
	})

	fmt.Printf("Added %q to approved_remotes. sir-protected agents can now push to this remote.\n", remote)
}

// cmdTrustMCP adds an MCP server to the trusted list (exempt from credential scanning).
// Same pattern as cmdAllowHost.
func cmdTrustMCP(projectRoot, serverName string) {
	if err := ensureManagedCommandAllowed("trust"); err != nil {
		fatal("%v", err)
	}
	stateDir := session.StateDir(projectRoot)
	leasePath := filepath.Join(stateDir, "lease.json")

	l, err := lease.Load(leasePath)
	if err != nil {
		fatal("load lease: %v", err)
	}

	// Check if already trusted
	if l.IsTrustedMCPServer(serverName) {
		fmt.Printf("MCP server %q is already in trusted_mcp_servers.\n", serverName)
		return
	}

	// Warn and confirm
	fmt.Println()
	fmt.Printf("  WARNING: Adding %q to trusted_mcp_servers will exempt it from\n", serverName)
	fmt.Printf("  credential argument scanning on every call, not just during\n")
	fmt.Printf("  secret sessions. Credential patterns in arguments will no longer\n")
	fmt.Printf("  be blocked for this server.\n")
	fmt.Println()
	fmt.Printf("  Only trust this server if it is designed to receive opaque tokens\n")
	fmt.Printf("  (e.g. a secrets-vault MCP) and you control it or trust the operator.\n")
	fmt.Println()
	fmt.Printf("  Trust %q? [y/N] ", serverName)

	var confirm string
	fmt.Scanln(&confirm)
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm != "y" && confirm != "yes" {
		fmt.Println("Cancelled. No changes made.")
		return
	}

	l.TrustedMCPServers = append(l.TrustedMCPServers, serverName)
	if err := l.Save(leasePath); err != nil {
		fatal("save lease: %v", err)
	}

	// Update LeaseHash in active session to prevent false-positive
	// integrity failures. session.Update holds the file lock across
	// the Load→mutate→Save sequence so concurrent CLI invocations
	// don't race — see CLAUDE.md rule 6.
	_ = session.Update(projectRoot, func(state *session.State) error {
		newHash, err := posture.HashLease(projectRoot)
		if err != nil {
			return err
		}
		state.LeaseHash = newHash
		return nil
	})

	// Log to ledger
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "trusted_mcp_servers",
		Decision: "allow",
		Reason:   fmt.Sprintf("added trusted MCP server: %s", serverName),
	})

	fmt.Printf("Added %q to trusted_mcp_servers. Credential scanning exempted for this server.\n", serverName)
}
