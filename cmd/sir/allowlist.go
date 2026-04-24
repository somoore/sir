package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

var afterLeaseSaveForTest func()

func cmdAllowHost(projectRoot, host string) {
	cmdAllowHostArgs(projectRoot, []string{host})
}

func cmdAllowHostArgs(projectRoot string, args []string) {
	if err := ensureManagedCommandAllowed("allow-host"); err != nil {
		fatal("%v", err)
	}
	if len(args) == 0 {
		fatal("usage: sir allow-host <hostname> [--ttl <duration>]")
	}
	host := args[0]
	var expiresAt time.Time
	for rest := args[1:]; len(rest) > 0; {
		arg := rest[0]
		rest = rest[1:]
		switch arg {
		case "--ttl":
			if len(rest) == 0 {
				fatal("--ttl requires a duration, e.g. 2h or 30m")
			}
			ttl, err := time.ParseDuration(rest[0])
			if err != nil {
				fatal("parse --ttl: %v", err)
			}
			expiresAt = time.Now().Add(ttl).UTC()
			rest = rest[1:]
		default:
			fatal("unknown flag: %s", arg)
		}
	}
	l, err := loadProjectLease(projectRoot)
	if err != nil {
		fatal("load lease: %v", err)
	}

	if expiresAt.IsZero() && l.IsApprovedHost(host) {
		fmt.Printf("Host %q is already in approved_hosts.\n", host)
		return
	}
	if !expiresAt.IsZero() {
		if l.IsApprovedHost(host) {
			fmt.Printf("Host %q is already approved; refreshing TTL.\n", host)
		}
	}

	// Warn and confirm
	fmt.Println()
	fmt.Printf("  WARNING: Adding %q to approved_hosts will allow sir-protected agents\n", host)
	fmt.Printf("  to make network requests to this destination without blocking.\n")
	if !expiresAt.IsZero() {
		fmt.Printf("  This approval expires at %s.\n", expiresAt.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Println()
	fmt.Printf("  Only add this host if you trust it completely.\n")
	fmt.Printf("  sir will no longer block egress to %s.\n", host)
	fmt.Println()
	fmt.Printf("  Add %q to approved_hosts? [y/N] ", host)

	var confirmText string
	fmt.Scanln(&confirmText)
	confirmText = strings.TrimSpace(strings.ToLower(confirmText))
	if confirmText != "y" && confirmText != "yes" {
		fmt.Println("Cancelled. No changes made.")
		return
	}

	if err := updateProjectLeaseAndSessionBaseline(projectRoot, func(l *lease.Lease) error {
		hostKey := strings.ToLower(host)
		l.ApprovedHosts = appendUniqueString(l.ApprovedHosts, host)
		if !expiresAt.IsZero() {
			if l.ApprovedHostExpires == nil {
				l.ApprovedHostExpires = make(map[string]time.Time)
			}
			l.ApprovedHostExpires[hostKey] = expiresAt
		} else if l.ApprovedHostExpires != nil {
			delete(l.ApprovedHostExpires, hostKey)
		}
		return nil
	}); err != nil {
		fatal("update lease/session baseline: %v", err)
	}

	reason := fmt.Sprintf("added host: %s", host)
	if !expiresAt.IsZero() {
		reason = fmt.Sprintf("added host: %s until %s", host, expiresAt.Format(time.RFC3339))
	}
	// Log to ledger
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "lease_modify",
		Target:   "approved_hosts",
		Decision: "allow",
		Reason:   reason,
	})

	if expiresAt.IsZero() {
		fmt.Printf("Added %q to approved_hosts. sir-protected agents can now reach this host.\n", host)
	} else {
		fmt.Printf("Added %q to approved_hosts until %s.\n", host, expiresAt.Format("2006-01-02 15:04:05 MST"))
	}
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
		missingLease := os.IsNotExist(err)
		if err != nil && !missingLease {
			return fmt.Errorf("load lease: %w", err)
		}
		l := lease.DefaultLease()
		if !missingLease {
			l, err = lease.Load(leasePath)
			if err != nil {
				return fmt.Errorf("load lease: %w", err)
			}
		}
		if err := mutate(l); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(leasePath), 0o700); err != nil {
			return fmt.Errorf("create lease dir: %w", err)
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
			if missingLease {
				if rollbackErr := os.Remove(leasePath); rollbackErr != nil && !os.IsNotExist(rollbackErr) {
					return fmt.Errorf("save session after lease update: %w (rollback lease removal: %v)", err, rollbackErr)
				}
			} else if rollbackErr := originalLease.Save(leasePath); rollbackErr != nil {
				return fmt.Errorf("save session after lease update: %w (rollback lease: %v)", err, rollbackErr)
			}
			return fmt.Errorf("save session after lease update: %w", err)
		}
		return nil
	})
}
