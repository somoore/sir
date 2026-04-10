// Package hooks — config_change.go handles the ConfigChange hook event.
// Fires when a host agent's configuration changes mid-session (model,
// permissions, hooks, MCP servers). Claude Code is the only agent that
// currently exposes this event natively; Gemini and Codex surface
// config drift post-hoc via the PostToolUse sentinel-hash check in
// post_evaluate.go and the session-terminal posture sweep in
// session_summary.go / session_end.go.
//
// sir logs every config change to the ledger and, for
// security-relevant keys, verifies posture integrity and hook tamper
// state — hook-subtree drift triggers session-fatal deny-all plus
// surgical auto-restore regardless of which agent fired the event.
package hooks

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

// ConfigChangePayload is the JSON structure received from the host
// agent for ConfigChange events. Field layout matches Claude Code's
// native ConfigChange payload, which is the only implementation
// wired through today.
type ConfigChangePayload struct {
	SessionID     string `json:"session_id"`
	HookEventName string `json:"hook_event_name"`
	ConfigKey     string `json:"config_key,omitempty"`
	OldValue      string `json:"old_value,omitempty"`
	NewValue      string `json:"new_value,omitempty"`
}

// EvaluateConfigChange is the ConfigChange hook handler.
// It logs configuration changes to the ledger and checks posture integrity
// for security-relevant changes.
func EvaluateConfigChange(projectRoot string, ag agent.Agent) error {
	// Read stdin
	limited := io.LimitReader(os.Stdin, maxPayloadBytes)
	data, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var payload ConfigChangePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	// Log the config change to ledger (never store values that might contain secrets)
	entry := &ledger.Entry{
		ToolName: "sir-hook",
		Verb:     "config_change",
		Target:   payload.ConfigKey,
		Decision: "allow",
		Reason:   "configuration changed",
	}
	if logErr := ledger.Append(projectRoot, entry); logErr != nil {
		fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
	}

	// For posture-related config changes, verify integrity
	if isPostureRelatedConfig(payload.ConfigKey) {
		lockErr := session.WithSessionLock(projectRoot, func() error {
			state, err := loadOptionalLifecycleSession(projectRoot, "config-change")
			if err != nil {
				return err
			}
			if state == nil {
				// No session — nothing to verify.
				return nil
			}

			l, err := loadLifecycleLease(projectRoot, "config-change")
			if err != nil {
				return err
			}

			// Verify posture integrity
			tampered := CheckPostureIntegrity(projectRoot, state, l)
			if len(tampered) > 0 {
				for _, f := range tampered {
					alertEntry := &ledger.Entry{
						ToolName:  "sir-hook",
						Verb:      "posture_change",
						Target:    f,
						Decision:  "alert",
						Reason:    fmt.Sprintf("posture file modified during config change: %s", payload.ConfigKey),
						Severity:  "HIGH",
						AlertType: "config_change_posture",
					}
					if logErr := ledger.Append(projectRoot, alertEntry); logErr != nil {
						fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
					}
					emitTelemetryEvent(alertEntry, state, ag)
				}
			}

			// Verify global hooks integrity across ALL host agents.
			// When the combined hash trips, detect which specific agent's
			// config drifted and restore that one — not a hardcoded path.
			if state.GlobalHookHash != "" {
				currentHash, hashErr := hashGlobalHooksFile()
				globalDrift := (hashErr == nil && currentHash != state.GlobalHookHash) || os.IsNotExist(hashErr)
				if globalDrift {
					changed, detectErr := DetectChangedGlobalHooksStrict()
					if detectErr != nil {
						state.SetDenyAll("managed hook baseline unavailable during config change: " + detectErr.Error())
						alertEntry := &ledger.Entry{
							ToolName:    "sir-hook",
							Verb:        "posture_tamper",
							Target:      "managed hooks",
							Decision:    "deny",
							Reason:      "managed hook baseline unavailable during config change",
							Severity:    "HIGH",
							AlertType:   "hook_tamper",
							DiffSummary: "baseline unavailable",
						}
						if logErr := ledger.Append(projectRoot, alertEntry); logErr != nil {
							fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
						}
						emitTelemetryEvent(alertEntry, state, ag)
						fmt.Fprintln(os.Stderr, FormatDenyAll(state.DenyAllReason))
						return state.Save()
					}
					if len(changed) == 0 && hashErr == nil {
						// Same reconciliation path as post_evaluate.go:
						// hash mismatched but no per-agent subtree drift,
						// so the stored hash is stale under the old
						// whole-file hashing semantics. Silently adopt
						// the new hash.
						state.GlobalHookHash = currentHash
					} else {
						target := FormatChangedHookTargets(changed)

						for _, f := range changed {
							diffSummary := managedHookDiffSummary(f)
							restored := AutoRestoreAgentHookFile(f)
							if restored {
								fmt.Fprintln(os.Stderr, FormatPostureRestore(f.DisplayPath))
							}
							alertEntry, logErr := appendHookTamperEntry(
								projectRoot,
								"sir-hook",
								f,
								"deny",
								"global hooks modified during config change — session-fatal",
								restored,
								diffSummary,
							)
							if logErr != nil {
								fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", logErr)
							}
							emitTelemetryEvent(alertEntry, state, ag)
						}

						state.SetDenyAll("global hooks modified during config change: " + target)

						fmt.Fprintln(os.Stderr, FormatHookTamper(target))
					}
				}
			}

			return state.Save()
		})
		if lockErr != nil {
			return fmt.Errorf("config-change: %w", lockErr)
		}
	}

	return nil
}

// isPostureRelatedConfig returns true if the config key relates to security posture.
func isPostureRelatedConfig(key string) bool {
	postureKeys := []string{
		"hooks", "permissions", "allowedTools", "mcpServers",
		"model", "customInstructions",
	}
	for _, pk := range postureKeys {
		if key == pk {
			return true
		}
	}
	return false
}
