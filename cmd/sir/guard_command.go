package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
)

type guardCommandHandler func(projectRoot string, ag agent.Agent)

var guardHandlers = map[string]guardCommandHandler{
	"evaluate": func(projectRoot string, ag agent.Agent) {
		if err := hooks.Evaluate(projectRoot, ag); err != nil {
			guardDeny(ag, "sir guard evaluate: %v", err)
		}
	},
	"post-evaluate": func(projectRoot string, ag agent.Agent) {
		// PostToolUse should never silently fail-open on unreadable state.
		if err := hooks.PostEvaluate(projectRoot, ag); err != nil {
			guardPostDeny(ag, "sir guard post-evaluate: %v", err)
		}
	},
	"permission-request": func(projectRoot string, ag agent.Agent) {
		// PermissionRequest — broker native permission prompts through sir policy.
		if err := hooks.EvaluatePermissionRequest(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "PermissionRequest", "sir guard permission-request: %v", err)
		}
	},
	"user-prompt": func(projectRoot string, ag agent.Agent) {
		// UserPromptSubmit — advance turn counter
		if err := hooks.EvaluateUserPrompt(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "UserPromptSubmit", "sir guard user-prompt: %v", err)
		}
	},
	"subagent-start": func(projectRoot string, ag agent.Agent) {
		// SubagentStart — check delegation policy
		if err := hooks.EvaluateSubagentStart(projectRoot, ag); err != nil {
			guardDeny(ag, "sir guard subagent-start: %v", err)
		}
	},
	"compact-reinject": func(projectRoot string, ag agent.Agent) {
		// SessionStart (compact) — reinject security reminders
		if err := hooks.EvaluateCompactReinject(projectRoot, ag); err != nil {
			fmt.Fprintf(os.Stderr, "sir: compact-reinject error: %v\n", err)
		}
	},
	"config-change": func(projectRoot string, ag agent.Agent) {
		// ConfigChange — log and verify posture
		if err := hooks.EvaluateConfigChange(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "ConfigChange", "sir guard config-change: %v", err)
		}
	},
	"instructions-loaded": func(projectRoot string, ag agent.Agent) {
		// InstructionsLoaded — hash instructions for tamper detection
		if err := hooks.EvaluateInstructionsLoaded(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "InstructionsLoaded", "sir guard instructions-loaded: %v", err)
		}
	},
	"session-summary": func(projectRoot string, ag agent.Agent) {
		// Stop — compute and log session summary
		if err := hooks.EvaluateSessionSummary(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "Stop", "sir guard session-summary: %v", err)
		}
	},
	"session-end": func(projectRoot string, ag agent.Agent) {
		// SessionEnd — finalize session
		if err := hooks.EvaluateSessionEnd(projectRoot, ag); err != nil {
			guardLifecycleDeny(ag, "SessionEnd", "sir guard session-end: %v", err)
		}
	},
	"elicitation": func(projectRoot string, ag agent.Agent) {
		// Elicitation hook: scan for credential harvesting.
		if err := hooks.EvaluateElicitation(projectRoot, ag); err != nil {
			fmt.Fprintf(os.Stderr, "sir: elicitation error: %v\n", err)
		}
	},
}

// parseAgentFlag scans guard-subcommand arguments for --agent <value> or
// --agent=<value> and returns the identifier, defaulting to "claude" when
// the flag is absent. Accepts any position in args so the flag can appear
// after the subcommand (e.g. "sir guard evaluate --agent codex").
//
// Backward compatibility: existing installs have hook commands like
// "sir guard evaluate" with no --agent flag. Those continue to work because
// the default is "claude".
func parseAgentFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--agent" {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		if strings.HasPrefix(a, "--agent=") {
			return strings.TrimPrefix(a, "--agent=")
		}
	}
	return string(agent.Claude)
}

// resolveAgent looks up an adapter by ID and falls back to Claude for
// unknown or empty IDs. Returns the adapter and a boolean indicating whether
// the requested ID was recognized — callers can use this to emit a warning
// for unknown agents without breaking the existing deny-fast behavior.
func resolveAgent(id string) (agent.Agent, bool) {
	ag := agent.ForID(agent.AgentID(id))
	if ag == nil {
		return agent.ForID(agent.Claude), false
	}
	return ag, true
}

func guardCommandNames() []string {
	out := make([]string, 0, len(guardHandlers))
	for name := range guardHandlers {
		out = append(out, name)
	}
	return out
}

func cmdGuard(projectRoot string, args []string) {
	if len(args) == 0 {
		guardDeny(nil, "sir guard: missing subcommand (evaluate|permission-request|post-evaluate|user-prompt|subagent-start|compact-reinject|config-change|instructions-loaded|session-summary|session-end|elicitation)")
	}

	agentID := string(agent.Claude)
	if len(args) > 1 {
		agentID = parseAgentFlag(args[1:])
	}
	ag, known := resolveAgent(agentID)
	if !known {
		guardDeny(ag, "sir guard: unknown --agent value: %q", agentID)
	}

	handler, ok := guardHandlers[args[0]]
	if !ok {
		guardDeny(ag, "sir guard: unknown subcommand: %s", args[0])
	}
	handler(projectRoot, ag)
}
