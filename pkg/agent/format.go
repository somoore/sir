// Package agent — shared response formatters.
//
// These helpers produce byte-exact output matching the pre-refactor
// adapters. The equivalence_test.go goldens are the contract: do not change
// these formatters unless you also update those goldens (which you should
// NOT do during the refactor — they are the safety net proving behavior is
// preserved).
package agent

import "encoding/json"

// formatClaudePreToolUse emits the Claude hookSpecificOutput envelope for a
// PreToolUse verdict.
func formatClaudePreToolUse(decision, reason string) ([]byte, error) {
	return json.Marshal(claudeHookResponse{
		HookSpecificOutput: claudeHookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       decision,
			PermissionDecisionReason: reason,
		},
	})
}

// formatLegacyPreToolUse emits the flat { decision, reason } shape used by
// Codex and Gemini. Allow -> {}; deny/ask -> {decision: denyLiteral, reason}.
// When hasAsk is false and decision is "ask", the AskToDenySuffix is folded
// into the reason so the developer sees the remediation path.
func formatLegacyPreToolUse(decision, reason, denyLiteral string, hasAsk bool) ([]byte, error) {
	if decision == "allow" {
		return []byte("{}"), nil
	}
	if decision == "ask" && !hasAsk {
		reason = reason + AskToDenySuffix
	}
	return json.Marshal(map[string]interface{}{
		"decision": denyLiteral,
		"reason":   reason,
	})
}

// formatLegacyPostToolUse emits the flat { decision, reason } shape for a
// PostToolUse verdict. When emitEnvelope is true, a hookSpecificOutput
// envelope with additionalContext is included alongside (used by Codex to
// mirror Claude's post-tool plumbing). When false (Gemini), only the flat
// fields are emitted.
func formatLegacyPostToolUse(decision, reason, denyLiteral string, hasAsk, emitEnvelope bool) ([]byte, error) {
	if decision == "allow" {
		return []byte("{}"), nil
	}
	if decision == "ask" && !hasAsk {
		reason = reason + AskToDenySuffixPost
	}
	out := map[string]interface{}{
		"decision": denyLiteral,
		"reason":   reason,
	}
	if emitEnvelope {
		out["hookSpecificOutput"] = map[string]interface{}{
			"hookEventName":     "PostToolUse",
			"additionalContext": reason,
		}
	}
	return json.Marshal(out)
}

// formatLegacyLifecycle emits the lifecycle response shape shared between
// Codex and Gemini. The two agents differ in a handful of small ways which
// are encoded as flags here rather than via an extra function pointer:
//
//   - Codex Stop emits {decision:"block",reason} ONLY when decision == "block"
//     literally (not "deny"). Gemini Stop always emits {}.
//   - Gemini UserPromptSubmit emits {decision:"deny",reason} on block/deny;
//     Codex UserPromptSubmit always emits {}.
//   - Gemini returns nil for unsupported events (ConfigChange, Elicitation,
//     InstructionsLoaded, SubagentStart). Codex returns {} for any unknown
//     event. Unsupported-event filtering is done by the caller via a
//     supported-events lookup — this helper just formats the known shapes.
//
// eventSupported indicates whether the event is in the agent's
// SupportedSIREvents list. When false, the Gemini-style contract returns
// nil bytes; the Codex-style contract returns {}. That distinction is
// controlled by the returnNilForUnsupported flag.
func formatLegacyLifecycle(
	spec *AgentSpec,
	eventName, decision, reason, context string,
	eventSupported bool,
) ([]byte, error) {
	denyLit := spec.LegacyDenyLiteral

	switch eventName {
	case "SessionStart":
		if context == "" {
			return []byte("{}"), nil
		}
		return json.Marshal(map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     "SessionStart",
				"additionalContext": context,
			},
		})

	case "Stop":
		// Codex: only literal "block" decision emits a body.
		// Gemini: Stop always emits {}.
		if spec.ID == Codex && decision == "block" {
			return json.Marshal(map[string]interface{}{
				"decision": "block",
				"reason":   reason,
			})
		}
		return []byte("{}"), nil

	case "UserPromptSubmit":
		// Gemini: deny/block emit a body. Codex: always {}.
		if spec.ID == Gemini && (decision == "deny" || decision == "block") {
			return json.Marshal(map[string]interface{}{
				"decision": denyLit,
				"reason":   reason,
			})
		}
		return []byte("{}"), nil

	case "SessionEnd":
		// Both agents: {}.
		return []byte("{}"), nil
	}

	// Unknown / unsupported events.
	if eventSupported {
		return []byte("{}"), nil
	}
	// Gemini returns nil for explicitly unsupported events; Codex returns {}.
	if spec.ID == Gemini {
		return nil, nil
	}
	return []byte("{}"), nil
}
