package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
)

func fatal(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, "sir: "+format+"\n", args...)
	os.Exit(1)
}

// guardDeny emits a well-formed PreToolUse deny response to stdout and exits 0.
// This ensures the host agent always receives a parseable JSON deny rather than
// interpreting a non-zero exit or missing JSON as a non-blocking warning
// (fail-open). Used exclusively in the "sir guard evaluate" path.
//
// The agent adapter is used to format the deny response in the agent's wire
// format. If ag is nil (unknown --agent flag), we fall back to Claude Code's
// format for backward compatibility with existing installs.
func guardDeny(ag agent.Agent, format string, args ...interface{}) {
	reason := fmt.Sprintf("sir INTERNAL ERROR: "+format, args...)
	fmt.Fprintf(os.Stderr, "%s\n", reason)
	if ag == nil {
		ag = &agent.ClaudeAgent{}
	}
	if data, err := ag.FormatPreToolUseResponse("deny", reason); err == nil {
		os.Stdout.Write(data) //nolint:errcheck
	} else {
		// Last-ditch fallback: emit a minimally-valid Claude Code deny envelope
		// so the host agent never sees non-JSON on stdout.
		fallback := map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": reason,
			},
		}
		if b, mErr := json.Marshal(fallback); mErr == nil {
			os.Stdout.Write(b) //nolint:errcheck
		}
	}
	os.Exit(0)
}

func lifecycleDecisionLiteral(ag agent.Agent, eventName string) string {
	if ag != nil && ag.ID() == agent.Codex && eventName == "Stop" {
		return "block"
	}
	return "deny"
}

func guardPostDeny(ag agent.Agent, format string, args ...interface{}) {
	reason := fmt.Sprintf("sir INTERNAL ERROR: "+format, args...)
	fmt.Fprintf(os.Stderr, "%s\n", reason)
	if ag == nil {
		ag = &agent.ClaudeAgent{}
	}
	if data, err := ag.FormatPostToolUseResponse("deny", reason); err == nil && len(data) > 0 {
		os.Stdout.Write(data) //nolint:errcheck
	}
	os.Exit(0)
}

func guardLifecycleDeny(ag agent.Agent, eventName, format string, args ...interface{}) {
	reason := fmt.Sprintf("sir INTERNAL ERROR: "+format, args...)
	fmt.Fprintf(os.Stderr, "%s\n", reason)
	if ag == nil {
		ag = &agent.ClaudeAgent{}
	}
	if data, err := ag.FormatLifecycleResponse(eventName, lifecycleDecisionLiteral(ag, eventName), reason, ""); err == nil && len(data) > 0 {
		os.Stdout.Write(data) //nolint:errcheck
	}
	os.Exit(0)
}
