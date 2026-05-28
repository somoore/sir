package relay

import (
	"fmt"
	"strings"

	"github.com/somoore/sir/pkg/telemetry"
)

// blockKitMessage renders a curated detection event as a Slack Block Kit
// message: a header, a section with the what/why/data/next narrative, and an
// actions block whose buttons carry the exact sir commands. Slack incoming
// webhooks accept the "blocks" array directly. The "text" field is a plain-text
// fallback for notifications and non-Block-Kit clients.
func blockKitMessage(ev telemetry.SlackEvent) map[string]any {
	header := fmt.Sprintf("[sir] %s %s", strings.ToUpper(ev.Severity), ev.Title)
	if len(header) > 150 {
		header = header[:150]
	}

	var body strings.Builder
	writeField(&body, "What", ev.What)
	if ev.Target != "" {
		writeField(&body, "Where", ev.Verb+" "+ev.Target)
	}
	writeField(&body, "Why", ev.Why)
	writeField(&body, "Data", ev.DataLeft)
	writeField(&body, "Next", ev.NextStep)
	if ev.LedgerIndex >= 0 {
		fmt.Fprintf(&body, "_ledger #%d", ev.LedgerIndex)
		if ev.ProjectHash != "" {
			fmt.Fprintf(&body, " · project %s", shortHash(ev.ProjectHash))
		}
		body.WriteString("_")
	}

	blocks := []any{
		map[string]any{
			"type": "header",
			"text": map[string]any{"type": "plain_text", "text": header},
		},
		map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": strings.TrimSpace(body.String())},
		},
	}

	if elements := actionButtons(ev.SuggestedActions); len(elements) > 0 {
		blocks = append(blocks, map[string]any{"type": "actions", "elements": elements})
	}

	return map[string]any{
		"text":   ev.Text, // plain-text fallback
		"blocks": blocks,
	}
}

func writeField(b *strings.Builder, label, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(b, "*%s:* %s\n", label, value)
}

// actionButtons builds Slack button elements from the suggested actions. Slack
// caps a single actions block at 5 elements; we keep the first few. The button
// value carries the exact command, echoed back on click by the interaction
// handler.
func actionButtons(actions []telemetry.SlackAction) []any {
	const maxButtons = 5
	elements := make([]any, 0, len(actions))
	for i, a := range actions {
		if i >= maxButtons {
			break
		}
		label := a.Label
		if label == "" {
			label = "Action"
		}
		if len(label) > 75 {
			label = label[:75]
		}
		elements = append(elements, map[string]any{
			"type":      "button",
			"text":      map[string]any{"type": "plain_text", "text": label},
			"value":     a.Command,
			"action_id": fmt.Sprintf("sir_action_%d", i),
		})
	}
	return elements
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// slackInteraction is the subset of Slack's interaction payload the relay reads:
// just the clicked action's command, carried in the button value. The relay
// replies in the HTTP response body, so it deliberately ignores the
// attacker-controllable response_url (reading it would invite an SSRF sink).
type slackInteraction struct {
	Actions []struct {
		Value string `json:"value"`
	} `json:"actions"`
}

func (p slackInteraction) command() string {
	for _, a := range p.Actions {
		if strings.TrimSpace(a.Value) != "" {
			return a.Value
		}
	}
	return ""
}
