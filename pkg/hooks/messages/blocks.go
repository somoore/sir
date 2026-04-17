package messages

import (
	"fmt"
	"strings"
	"time"
)

func formatBlockAgentAction(agentName, action, why string, fixLines []string) string {
	if agentName == "" {
		agentName = "Claude"
	}
	var b strings.Builder
	b.WriteString(agentName)
	b.WriteString(" tried to ")
	b.WriteString(action)
	b.WriteString(" — ")
	b.WriteString(colorize(colorBold+colorRed, "\u00d7 deny"))
	b.WriteString(".\n\n")
	b.WriteString("  reason: ")
	b.WriteString(why)
	b.WriteString("\n\n")
	b.WriteString("  fix:    ")
	for i, line := range fixLines {
		if i > 0 {
			b.WriteString("          ")
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	b.WriteString("\n  details: ")
	b.WriteString(colorize(colorDim, "sir why"))
	return b.String()
}

func FormatBlockNetExternal(agentName, dest string, secretReadTime time.Time) string {
	host, hasHost := ExtractHostForMessage(dest)
	if !hasHost {
		host = "an external host"
	}
	if secretReadTime.IsZero() {
		fixLines := []string{}
		if hasHost {
			fixLines = append(fixLines, fmt.Sprintf("sir allow-host %s   (run in YOUR terminal, not from the agent)", host))
		}
		fixLines = append(fixLines, "sir unlock                       (only if a secret read locked you)")
		return formatBlockAgentAction(agentName,
			"reach "+host,
			"External network requests are off by default. (Reading credentials\n          earlier in this session would also block this — neither applies\n          silently.)",
			fixLines,
		)
	}

	timestamp := secretReadTime.Format("15:04")
	fixLines := []string{
		"Wait — the lock clears when the agent finishes responding.",
		"sir unlock                       (run in YOUR terminal, not from the agent)",
	}
	if hasHost {
		fixLines = append(fixLines,
			fmt.Sprintf("sir allow-host %s   (YOUR terminal, only if you trust this host)", host))
	}
	return formatBlockAgentAction(agentName,
		"reach "+host,
		fmt.Sprintf("You approved reading a credentials file at %s, so sir is\n          restricting external network until this turn ends.", timestamp),
		fixLines,
	)
}

func FormatBlockEgress(agentName, dest string, secretReadTime time.Time) string {
	return FormatBlockNetExternal(agentName, dest, secretReadTime)
}

func FormatBlockPush(agentName, remote string, secretReadTime time.Time) string {
	timestamp := secretReadTime.Format("15:04")
	return formatBlockAgentAction(agentName,
		"push to "+remote,
		fmt.Sprintf("You approved reading a credentials file at %s, so sir is\n          restricting pushes to unapproved remotes until this turn ends.", timestamp),
		[]string{
			"Wait — the lock clears when the agent finishes responding.",
			fmt.Sprintf("sir allow-remote %s   (only if you actually trust this remote)", remote),
			"sir unlock                       (lift the lock now)",
		},
	)
}

func FormatBlockDelegation(agentName string) string {
	return formatBlockAgentAction(agentName,
		"spawn a sub-agent while this session may contain credentials",
		"Sub-agents inherit the parent's secret-session flag, but the model has\n          no way to enforce that handoff. Delegation in a secret session is\n          blocked to prevent secret laundering.",
		[]string{
			"Wait — the lock clears when the agent finishes responding.",
			"sir unlock                       (lift the lock now, then retry)",
		},
	)
}

func FormatBlockDNS(agentName, target string, secretReadTime time.Time) string {
	if secretReadTime.IsZero() {
		return formatBlockAgentAction(agentName,
			"run a DNS lookup ("+target+")",
			"DNS lookups are blocked by default — they can encode data in\n          hostnames and exfiltrate it through any approved resolver.",
			[]string{
				"Use curl or wget to an approved host instead.",
				"There is no `unlock` for DNS — it is always blocked.",
			},
		)
	}
	timestamp := secretReadTime.Format("15:04")
	return formatBlockAgentAction(agentName,
		"run a DNS lookup ("+target+")",
		fmt.Sprintf("You approved reading a credentials file at %s. DNS lookups can\n          leak data encoded in hostnames and are always blocked.", timestamp),
		[]string{
			"Use curl or wget to an approved host instead.",
			"sir unlock                       (clears transient runtime restrictions; DNS still blocked)",
		},
	)
}
