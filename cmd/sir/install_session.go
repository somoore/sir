package main

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// cmdClearSession clears the session secret flag and other session restrictions.
// Pressure-valve command for developers who want to restore network access without
// starting a new Claude session.
func cmdClearSession(projectRoot string) {
	existing, err := session.Load(projectRoot)
	if err != nil {
		fatal("no active session found: %v", err)
	}
	if !existing.SecretSession {
		fmt.Println("Session does not carry secret labels. Nothing to clear.")
		return
	}

	if err := session.Update(projectRoot, func(state *session.State) error {
		state.ClearSecretSession()
		return nil
	}); err != nil {
		fatal("clear session: %v", err)
	}

	entry := &ledger.Entry{
		ToolName: "sir-cli",
		Verb:     "session_cleared",
		Target:   "secret_session",
		Decision: "allow",
		Reason:   "developer lifted secret-session lock via sir unlock",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not log to ledger: %v\n", err)
	}

	fmt.Println(hooks.FormatSessionCleared())
}

func cmdUninstall(projectRoot string) {
	explicit := parseInstallAgentFlag(os.Args[2:])

	var agents []agent.Agent
	if explicit != "" {
		ag := agent.ForID(agent.AgentID(explicit))
		if ag == nil {
			fatal("unknown agent: %s (supported: %s)", explicit, supportedAgentIDs())
		}
		agents = []agent.Agent{ag}
	} else {
		agents = agent.All()
	}

	anyRemoved := false
	for _, ag := range agents {
		removed, err := uninstallForAgent(ag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: uninstall %s hooks: %v\n", ag.Name(), err)
			continue
		}
		if removed {
			anyRemoved = true
		}
	}

	if !anyRemoved {
		fmt.Println("No sir hooks found in any known agent config.")
	}
	fmt.Println("sir uninstalled. State preserved at ~/.sir/ for forensic review.")
}
