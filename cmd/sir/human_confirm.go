package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// humanConfirmation is the confirmation channel for CLI commands that widen
// the agent's authority. Tests replace it; the production implementation
// reads from the controlling terminal (/dev/tty), never stdin, so a command
// run by an agent with piped input cannot answer its own prompt.
var humanConfirmation = confirmOnControllingTerminal

// requireHumanConfirmation fails closed unless a human at a real terminal
// explicitly confirms. This is the out-of-band check for `sir approve`,
// `sir unprotect-path`, `sir policy init`, `sir mcp approve`, and the other
// authority-mutating verbs: the agent's Bash tool has no controlling
// terminal, so `sir approve --last --session` cannot self-grant.
func requireHumanConfirmation(action string) {
	if err := humanConfirmation(action); err != nil {
		fatal("%v", err)
	}
}

func confirmOnControllingTerminal(action string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("refusing to %s without an interactive terminal: this grants the agent authority and requires human confirmation (run it from your own terminal)", action)
	}
	defer tty.Close()

	fmt.Fprintf(tty, "sir: %s changes agent authority.\nType 'yes' to confirm: ", action)
	line, readErr := bufio.NewReader(io.LimitReader(tty, 64)).ReadString('\n')
	if readErr != nil && readErr != io.EOF {
		return fmt.Errorf("read confirmation: %w", readErr)
	}
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		return fmt.Errorf("confirmation declined; no changes made")
	}
	return nil
}

// policyCommandIsReadOnly reports whether `sir policy <args>` only inspects
// policy. Anything unrecognised is treated as mutating (fail closed).
func policyCommandIsReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	switch strings.ToLower(args[0]) {
	case "show", "diff", "suggest":
		return true
	}
	return false
}

// mcpCommandIsReadOnly reports whether `sir mcp <args>` only inspects MCP
// state. It mirrors the routing in cmdMCP and cmdMCPScope: a flag-only
// invocation defaults to status, and `scope` with no server (or `scope list`)
// only lists scopes. Anything unrecognised is treated as mutating (fail
// closed).
func mcpCommandIsReadOnly(args []string) bool {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return true
	}
	switch strings.ToLower(args[0]) {
	case "status", "inventory", "list":
		return true
	case "scope":
		rest := withoutProjectFlag(args[1:])
		return len(rest) == 0 || rest[0] == "list"
	}
	return false
}

// withoutProjectFlag drops `--project <path>` and `--project=<path>` the way
// extractProjectFlag does, without resolving or validating the path.
func withoutProjectFlag(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--project":
			i++
		case strings.HasPrefix(args[i], "--project="):
		default:
			out = append(out, args[i])
		}
	}
	return out
}

// logCommandIsReadOnly reports whether `sir log <args>` only reads the audit
// trail. Archive truncates the live chain and is therefore mutating.
func logCommandIsReadOnly(args []string) bool {
	if len(args) == 0 {
		return true
	}
	return strings.ToLower(args[0]) != "archive"
}
