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
	cmdApproveGrant(projectRoot, lastAsk.Verb, lastAsk.Target, args, fmt.Sprintf("approved ledger entry #%d", lastAsk.Index))
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
