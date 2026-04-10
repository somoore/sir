package hooks

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/agent"
	hookslifecycle "github.com/somoore/sir/pkg/hooks/lifecycle"
	hookmessages "github.com/somoore/sir/pkg/hooks/messages"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func rebaselinePostureHashesAfterWrite(payload *PostHookPayload, state *session.State, l *lease.Lease, projectRoot string) {
	if payload.ToolName != "Write" && payload.ToolName != "Edit" {
		return
	}
	target := extractPostEvaluateTarget(payload)
	if target != "" && IsPostureFileResolved(target, l) {
		state.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	}
}

func handleBashPostEvaluateChecks(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string, ag agent.Agent) (*HookResponse, bool) {
	if payload.ToolName != "Bash" {
		return nil, false
	}
	if tamperResp, handled := handlePostureIntegrityDrift(payload, l, state, projectRoot, ag); handled {
		return tamperResp, true
	}
	if hookResp, handled := handleGlobalHookIntegrityDrift(payload, state, projectRoot, ag); handled {
		return hookResp, true
	}
	return nil, false
}

func handlePostureIntegrityDrift(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string, ag agent.Agent) (*HookResponse, bool) {
	drift := hookslifecycle.DetectPostureIntegrityDrift(projectRoot, state, l)
	if len(drift.NonHookFiles) == 0 && len(drift.HookFiles) == 0 {
		return nil, false
	}

	if len(drift.HookFiles) == 0 {
		for _, f := range drift.NonHookFiles {
			entry := &ledger.Entry{
				ToolName:  payload.ToolName,
				Verb:      "posture_change",
				Target:    f,
				Decision:  "alert",
				Reason:    fmt.Sprintf("posture file modified: %s", f),
				Severity:  "MEDIUM",
				AlertType: "posture_change",
			}
			if err := ledger.Append(projectRoot, entry); err != nil {
				fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
			}
			emitTelemetryEvent(entry, state, ag)
		}
		return nil, false
	}

	targets := make([]string, 0, len(drift.HookFiles))
	for _, hookFile := range drift.HookFiles {
		diffSummary := managedHookDiffSummary(hookFile)
		restored := AutoRestoreAgentHookFile(hookFile)
		targets = append(targets, hookFile.RelativePath)
		entry, err := appendHookTamperEntry(
			projectRoot,
			payload.ToolName,
			hookFile,
			"deny",
			"security configuration was modified unexpectedly - all tool calls blocked",
			restored,
			diffSummary,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		}
		emitTelemetryEvent(entry, state, ag)
		if restored {
			fmt.Fprintln(os.Stderr, hookmessages.FormatPostureRestore(hookFile.RelativePath))
		}
	}
	target := joinWithComma(targets)
	state.SetDenyAll(fmt.Sprintf("posture file tampered: %s", target))
	return &HookResponse{
		Decision: "deny",
		Reason:   hookmessages.FormatHookTamper(target),
	}, true
}

func handleGlobalHookIntegrityDrift(payload *PostHookPayload, state *session.State, projectRoot string, ag agent.Agent) (*HookResponse, bool) {
	drift := hookslifecycle.DetectGlobalHookIntegrityDrift(state)
	if drift == nil {
		return nil, false
	}
	if drift.BaselineErr != nil {
		state.SetDenyAll("managed hook baseline unavailable: " + drift.BaselineErr.Error())
		entry := &ledger.Entry{
			ToolName:    payload.ToolName,
			Verb:        "posture_tamper",
			Target:      "managed hooks",
			Decision:    "deny",
			Reason:      "managed hook baseline unavailable during drift check",
			Severity:    "HIGH",
			AlertType:   "hook_tamper",
			DiffSummary: "baseline unavailable",
		}
		if err := ledger.Append(projectRoot, entry); err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		}
		emitTelemetryEvent(entry, state, ag)
		return &HookResponse{
			Decision: "deny",
			Reason:   hookmessages.FormatDenyAll(state.DenyAllReason),
		}, true
	}
	if len(drift.Changed) == 0 && drift.CurrentHashKnown {
		state.GlobalHookHash = drift.CurrentHash
		return nil, false
	}

	target := FormatChangedHookTargets(drift.Changed)
	for _, f := range drift.Changed {
		diffSummary := managedHookDiffSummary(f)
		restored := AutoRestoreAgentHookFile(f)
		if restored {
			fmt.Fprintln(os.Stderr, hookmessages.FormatPostureRestore(f.DisplayPath))
		}
		entry, err := appendHookTamperEntry(
			projectRoot,
			payload.ToolName,
			f,
			"deny",
			"global sir hooks were modified unexpectedly - all tool calls blocked",
			restored,
			diffSummary,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append error: %v\n", err)
		}
		emitTelemetryEvent(entry, state, ag)
	}
	state.SetDenyAll("global hooks file tampered: " + target)
	return &HookResponse{
		Decision: "deny",
		Reason:   hookmessages.FormatHookTamper(target),
	}, true
}
