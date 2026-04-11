package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

var afterLeaseSaveForTest func()

func cmdAllowHost(projectRoot, host string) {
	if err := ensureManagedCommandAllowed("allow-host"); err != nil {
		fatal("%v", err)
	}
	l, err := loadProjectLease(projectRoot)
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

	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		l.ApprovedHosts = append(l.ApprovedHosts, host)
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

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
	l, err := loadProjectLease(projectRoot)
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

	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		l.ApprovedRemotes = append(l.ApprovedRemotes, remote)
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

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
	l, err := loadProjectLease(projectRoot)
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

	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		l.TrustedMCPServers = append(l.TrustedMCPServers, serverName)
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

	// Log to ledger
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "trusted_mcp_servers",
		Decision: "allow",
		Reason:   fmt.Sprintf("added trusted MCP server: %s", serverName),
	})

	fmt.Printf("Added %q to trusted_mcp_servers. Credential scanning exempted for this server.\n", serverName)
}

func loadProjectLease(projectRoot string) (*lease.Lease, error) {
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	return lease.Load(leasePath)
}

func updateProjectLeaseAndSessionBaseline(projectRoot string, mutate func(*lease.Lease) error) error {
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")

	return session.WithSessionLock(projectRoot, func() error {
		state, err := session.Load(projectRoot)
		missingSession := os.IsNotExist(err)
		if err != nil && !missingSession {
			return fmt.Errorf("load session for lease update: %w", err)
		}

		originalLease, err := lease.Load(leasePath)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		l, err := lease.Load(leasePath)
		if err != nil {
			return fmt.Errorf("load lease: %w", err)
		}
		if err := mutate(l); err != nil {
			return err
		}
		if err := l.Save(leasePath); err != nil {
			return fmt.Errorf("save lease: %w", err)
		}
		if afterLeaseSaveForTest != nil {
			afterLeaseSaveForTest()
		}
		if missingSession {
			return nil
		}

		newHash, err := posture.HashLease(projectRoot)
		if err != nil {
			return fmt.Errorf("hash updated lease: %w", err)
		}
		state.LeaseHash = newHash
		if err := state.Save(); err != nil {
			if rollbackErr := originalLease.Save(leasePath); rollbackErr != nil {
				return fmt.Errorf("save session after lease update: %w (rollback lease: %v)", err, rollbackErr)
			}
			return fmt.Errorf("save session after lease update: %w", err)
		}
		return nil
	})
}
