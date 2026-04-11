// Package hooks — subagent.go handles the SubagentStart hook event.
// Fires when the host agent launches a sub-agent. Claude Code is the
// only agent with a native SubagentStart event today; Gemini CLI and
// Codex do not expose sub-agent lifecycle hooks, so delegation
// gating is Claude-Code-only in practice. Checks lease.AllowDelegation,
// session secret state, and posture integrity before allowing delegation.
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// SubagentPayload is the JSON structure received from Claude Code for SubagentStart.
type SubagentPayload struct {
	SessionID     string   `json:"session_id"`
	HookEventName string   `json:"hook_event_name"`
	AgentName     string   `json:"agent_name,omitempty"`
	Tools         []string `json:"tools,omitempty"`
}

// EvaluateSubagentStart is the SubagentStart hook handler.
// It checks delegation policy: lease permission, secret session state,
// and posture integrity.
func EvaluateSubagentStart(projectRoot string, ag agent.Agent) error {
	// Read stdin
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload SubagentPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Load lease
	l, err := loadLease(projectRoot)
	if err != nil {
		return fmt.Errorf("load lease: %w", err)
	}

	var resp *HookResponse
	lockErr := session.WithSessionLock(projectRoot, func() error {
		state, sErr := session.Load(projectRoot)
		if sErr != nil {
			if os.IsNotExist(sErr) {
				// No session yet — session will be created on first PreToolUse.
				// Allow this SubagentStart through; the PreToolUse hook will
				// enforce policy for any tool call the sub-agent makes.
				return nil
			}
			// Corruption, permission denied, IO error — fail closed.
			// Returning an error causes the outer handler to exit via
			// guardDeny (see cmd/sir/main.go), emitting a deny response.
			return fmt.Errorf("load session: %w", sErr)
		}

		// Check session-fatal deny-all
		if state.DenyAll {
			resp = &HookResponse{
				Decision: policy.VerdictDeny,
				Reason:   FormatDenyAll(state.DenyAllReason),
			}
			return nil
		}

		// Check lease delegation permission
		if !l.AllowDelegation {
			resp = &HookResponse{
				Decision: policy.VerdictDeny,
				Reason: FormatBlock(
					"sub-agent delegation",
					"Lease does not allow agent delegation (allow_delegation = false).",
					"Update lease to allow delegation: sir install",
				),
			}
			logSubagentDecision(projectRoot, payload.AgentName, "deny", "lease disallows delegation")
			return nil
		}

		// Check secret session — deny (matching mister-core policy.rs).
		// CLAUDE.md invariant: "Sub-agents inherit parent's secret_session
		// flag — secrets cannot be laundered through delegation." The Go
		// layer must never be more permissive than Rust; policy.rs returns
		// deny for the delegate verb when secret_session is true.
		if state.SecretSession {
			resp = &HookResponse{
				Decision: policy.VerdictDeny,
				Reason: FormatBlock(
					fmt.Sprintf("sub-agent delegation (%s)", payload.AgentName),
					"Delegation blocked — your session contains credentials. Approving "+
						"would give the sub-agent tool capabilities that could access those "+
						"credentials, and sir cannot track IFC labels across the delegation "+
						"boundary.",
					"Wait — the lock clears when Claude finishes responding.\n"+
						"       sir unlock                       (lift the lock now, then retry)",
				),
			}
			logSubagentDecision(projectRoot, payload.AgentName, "deny", "secret session active")
			return nil
		}

		// Check posture integrity
		tampered := CheckPostureIntegrity(projectRoot, state, l)
		if len(tampered) > 0 {
			state.SetDenyAll(fmt.Sprintf("posture tampered before delegation: %v", tampered))
			if saveErr := state.Save(); saveErr != nil {
				fmt.Fprintf(os.Stderr, "sir: save session error: %v\n", saveErr)
			}
			resp = &HookResponse{
				Decision: policy.VerdictDeny,
				Reason:   FormatDenyAll(state.DenyAllReason),
			}
			return nil
		}

		if delegationRequiresApproval(state) {
			resp = &HookResponse{
				Decision: policy.VerdictAsk,
				Reason:   FormatAskPostureElevated("delegate", fmt.Sprintf("delegate to sub-agent: %s", payload.AgentName), string(state.Posture), state.MCPInjectionSignals),
			}
			logSubagentDecision(projectRoot, payload.AgentName, "ask", "tainted/elevated/pending-injection session")
			return nil
		}

		// Check if sub-agent has dangerous tools (network, file write to posture)
		hasDangerousTools := false
		for _, tool := range payload.Tools {
			if tool == "Bash" || tool == "Write" || tool == "Edit" {
				hasDangerousTools = true
				break
			}
		}

		// If recently read untrusted content, ask before delegating to agent with dangerous tools
		if state.RecentlyReadUntrusted && hasDangerousTools {
			resp = &HookResponse{
				Decision: policy.VerdictAsk,
				Reason: FormatAsk(
					fmt.Sprintf("delegate to sub-agent: %s", payload.AgentName),
					"Session recently read untrusted content. Sub-agent has tools that could act on it.",
					"Review the delegation carefully.",
				),
			}
			logSubagentDecision(projectRoot, payload.AgentName, "ask", "untrusted content + dangerous tools")
			return nil
		}

		// Allow delegation
		logSubagentDecision(projectRoot, payload.AgentName, "allow", "clean session, delegation permitted")
		return nil
	})
	if lockErr != nil {
		return fmt.Errorf("subagent-start: %w", lockErr)
	}

	if resp != nil {
		return writeSubagentResponse(os.Stdout, resp, ag)
	}
	// No response means allow — exit silently
	return nil
}

func logSubagentDecision(projectRoot, agentName, decision, reason string) {
	entry := &ledger.Entry{
		ToolName: "sir-hook",
		Verb:     string(policy.VerbDelegate),
		Target:   agentName,
		Decision: decision,
		Reason:   reason,
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
	}
}

func writeSubagentResponse(w io.Writer, resp *HookResponse, ag agent.Agent) error {
	data, err := ag.FormatLifecycleResponse("SubagentStart", string(resp.Decision), resp.Reason, "")
	if err != nil {
		return err
	}
	if data == nil {
		return nil
	}
	_, err = w.Write(data)
	return err
}
