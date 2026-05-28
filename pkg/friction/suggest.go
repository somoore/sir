package friction

import (
	"fmt"
	"sort"

	"github.com/somoore/sir/pkg/detect"
)

// minHitsForSuggestion is the friction floor below which a scoped lease is not
// worth recommending — a single one-off block is noise, not a pattern.
const minHitsForSuggestion = 2

// buildSuggestions turns observed friction into narrow, expiring lease
// recommendations. Each suggestion names the exact command to apply, so the
// developer (or `sir policy suggest`) can act without guessing. Suggestions
// are intentionally scoped (TTL host leases, single remotes, single servers)
// rather than broad trust grants.
func buildSuggestions(hostFriction, mcpFriction map[string]int, detCounts map[string]int) []Suggestion {
	var out []Suggestion

	for _, c := range topCounts(hostFriction, 0) {
		if c.N < minHitsForSuggestion {
			continue
		}
		out = append(out, Suggestion{
			Action:  "allow_host",
			Target:  c.Key,
			Command: fmt.Sprintf("sir allow-host %s --ttl 15m", c.Key),
			Reason:  fmt.Sprintf("%d prompts/blocks reaching this host; a narrow TTL lease removes the repeated friction", c.N),
			Hits:    c.N,
		})
	}

	for _, c := range topCounts(mcpFriction, 0) {
		if c.N < minHitsForSuggestion || c.Key == "(unknown)" {
			continue
		}
		out = append(out, Suggestion{
			Action:  "approve_mcp",
			Target:  c.Key,
			Command: fmt.Sprintf("sir mcp approve %s", c.Key),
			Reason:  fmt.Sprintf("%d prompts/blocks for this MCP server; approving it ends onboarding friction", c.N),
			Hits:    c.N,
		})
	}

	// Repeated secret→push friction is a likely sign the developer wants a
	// specific remote allowlisted rather than clearing taint each turn.
	if detCounts[string(detect.SecretToPushRemote)] >= minHitsForSuggestion {
		out = append(out, Suggestion{
			Action:  "allow_remote",
			Target:  "origin",
			Command: "sir allow-remote <remote-name>",
			Reason:  fmt.Sprintf("%d secret-context push blocks; allowlist the trusted remote or clear taint at a turn boundary with `sir unlock`", detCounts[string(detect.SecretToPushRemote)]),
			Hits:    detCounts[string(detect.SecretToPushRemote)],
		})
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Hits > out[j].Hits })
	return out
}
