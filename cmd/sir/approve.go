package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func cmdApprove(projectRoot string, args []string) {
	if len(args) == 0 {
		fatal("usage: sir approve --last [--session|--once] [--ttl <duration>]\n       sir approve host <host> [--ttl <duration>]\n       sir approve remote <name>\n       sir approve mcp <name>\n       sir approve path <path> [--session|--once]")
	}
	switch args[0] {
	case "--last", "last":
		cmdApproveLast(projectRoot, args[1:])
	case "host":
		if len(args) < 2 {
			fatal("usage: sir approve host <host> [--ttl <duration>]")
		}
		cmdAllowHostArgs(projectRoot, args[1:])
	case "remote":
		if len(args) != 2 {
			fatal("usage: sir approve remote <name>")
		}
		cmdAllowRemote(projectRoot, args[1])
	case "mcp":
		if len(args) < 2 {
			fatal("usage: sir approve mcp <name> [<name> ...]")
		}
		cmdMCPApprove(projectRoot, args[1:])
	case "path":
		if len(args) < 2 {
			fatal("usage: sir approve path <path> [--session|--once] [--ttl <duration>]")
		}
		cmdApproveGrant(projectRoot, "read_ref", args[1], args[2:], "manual path approval")
	default:
		fatal("unknown approve target: %s", args[0])
	}
}

func cmdApproveLast(projectRoot string, args []string) {
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		fatal("read ledger: %v", err)
	}
	var lastAsk *ledger.Entry
	for i := len(entries) - 1; i >= 0; i-- {
		if entries[i].Decision == "ask" {
			lastAsk = &entries[i]
			break
		}
	}
	if lastAsk == nil {
		fmt.Println("No ask decision found in the ledger; nothing to approve.")
		return
	}

	// Prefer turning the approval into a narrow, expiring lease so the same
	// prompt stops recurring — instead of a brittle one-shot grant that only
	// matches the exact target and re-asks on the next slightly different URL.
	// --once/--session force the old grant behavior; security-sensitive intents
	// (secret reads, posture, sudo, persistence, delegation) are never leased
	// and always fall through to an explicit one-shot grant.
	if !approveForcesGrant(args) {
		if kind, target, ok := leaseableApproval(*lastAsk); ok {
			fmt.Printf("Last ask was %s for %q — creating a scoped lease so it stops prompting.\n", lastAsk.Verb, target)
			switch kind {
			case "host":
				cmdAllowHostArgs(projectRoot, hostLeaseArgs(target, args))
			case "remote":
				cmdAllowRemote(projectRoot, target)
			case "mcp":
				cmdMCPApprove(projectRoot, []string{target})
			}
			return
		}
	}
	cmdApproveGrant(projectRoot, lastAsk.Verb, lastAsk.Target, args, fmt.Sprintf("approved ledger entry #%d", lastAsk.Index))
}

// approveForcesGrant reports whether the developer explicitly asked for the
// one-shot/session grant behavior instead of a lease.
func approveForcesGrant(args []string) bool {
	for _, a := range args {
		if a == "--once" || a == "--session" {
			return true
		}
	}
	return false
}

// leaseableApproval maps an ask entry to a scoped-lease action when the intent
// is a low-risk friction prompt (host egress, push to origin, MCP onboarding).
// Security-sensitive verbs return ok=false so they stay one-shot grants.
func leaseableApproval(e ledger.Entry) (kind, target string, ok bool) {
	switch e.Verb {
	case "net_external", "net_allowlisted":
		if h := approveHostFromTarget(e.Target); h != "" {
			return "host", h, true
		}
	case "push_origin":
		return "remote", "origin", true
	case "mcp_onboarding", "mcp_unapproved", "mcp_network_unapproved":
		if s := approveMCPServer(e.ToolName); s != "" {
			return "mcp", s, true
		}
	}
	return "", "", false
}

// hostLeaseArgs builds allow-host args from an ask, defaulting to a narrow 15m
// TTL unless the developer passed their own --ttl.
func hostLeaseArgs(host string, args []string) []string {
	for i := 0; i < len(args); i++ {
		if args[i] == "--ttl" && i+1 < len(args) {
			return []string{host, "--ttl", args[i+1]}
		}
	}
	return []string{host, "--ttl", "15m"}
}

// approveHostFromTarget extracts a bare hostname from a network target,
// stripping scheme, userinfo, path, and port. Returns "" when none is present.
func approveHostFromTarget(target string) string {
	s := strings.TrimSpace(target)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// approveMCPServer extracts the server name from an "mcp__<server>__<tool>"
// tool name, or "" for non-MCP tools.
func approveMCPServer(toolName string) string {
	if !strings.HasPrefix(toolName, "mcp__") {
		return ""
	}
	rest := strings.TrimPrefix(toolName, "mcp__")
	if i := strings.Index(rest, "__"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func cmdApproveGrant(projectRoot, verb, target string, args []string, reason string) {
	scope := "once"
	ttl := 15 * time.Minute
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--session":
			scope = "session"
			ttl = 0
		case "--once":
			scope = "once"
		case "--ttl":
			if i+1 >= len(args) {
				fatal("--ttl requires a duration")
			}
			parsed, err := time.ParseDuration(args[i+1])
			if err != nil {
				fatal("parse --ttl: %v", err)
			}
			ttl = parsed
			i++
		default:
			fatal("unknown flag: %s", args[i])
		}
	}
	uses := 1
	if scope == "session" {
		uses = 0
	}
	var expiresAt time.Time
	if ttl > 0 {
		expiresAt = time.Now().Add(ttl).UTC()
	}
	grant := session.ApprovalGrant{
		Verb:          verb,
		Target:        target,
		Scope:         scope,
		ExpiresAt:     expiresAt,
		UsesRemaining: uses,
		Reason:        reason,
	}
	if err := session.WithSessionLock(projectRoot, func() error {
		state, err := session.Load(projectRoot)
		if os.IsNotExist(err) {
			state = session.NewState(projectRoot)
		} else if err != nil {
			return err
		}
		state.AddApprovalGrant(grant)
		return state.Save()
	}); err != nil {
		fatal("save approval grant: %v", err)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		Verb:     "approval_grant",
		Target:   verb + ":" + target,
		Decision: "allow",
		Reason:   reason,
	})
	suffix := ""
	if !expiresAt.IsZero() {
		suffix = " until " + expiresAt.Format("15:04:05")
	}
	fmt.Printf("Approved next %s/%s retry (%s%s).\n", strings.TrimSpace(verb), strings.TrimSpace(target), scope, suffix)
}
