package hooks

import (
	"fmt"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// formatDenyReason produces human-readable block messages with causal chain.
func formatDenyReason(originalReason string, intent Intent, state *session.State, ag agent.Agent) string {
	secretSince := state.SecretSessionSince
	if !state.SecretSession {
		secretSince = time.Time{}
	}
	agentName := "Claude"
	if ag != nil {
		agentName = AgentDisplayName(string(ag.ID()))
	}
	switch intent.Verb {
	case policy.VerbNetExternal:
		return FormatBlockNetExternal(agentName, intent.Target, secretSince)
	case policy.VerbPushRemote:
		remote := intent.RemoteName
		if remote == "" {
			remote = "origin"
		}
		return FormatBlockPush(agentName, remote, secretSince)
	case policy.VerbDnsLookup:
		return FormatBlockDNS(agentName, intent.Target, secretSince)
	}
	return FormatBlock(
		fmt.Sprintf("%s: %s", intent.Verb, intent.Target),
		originalReason,
		"sir doctor                       (diagnose the block)\n       sir why                          (explain the most recent decision)",
	)
}
