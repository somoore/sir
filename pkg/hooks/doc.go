// Package hooks implements sir's hook handlers and the supporting logic that
// turns raw agent events into policy decisions, messages, and state updates.
//
// Contributor reading order:
//   - evaluate.go plus evaluate_*.go: the PreToolUse path, including payload
//     loading, intent classification, policy requests, and telemetry.
//   - post_evaluate.go plus post_evaluate_checks.go: the PostToolUse path for
//     output scanning, evidence capture, tamper checks, and posture changes.
//   - pkg/hooks/classify plus toolmap.go/toolmap_*.go: shell/tool
//     classification, especially the Bash-path logic used by Codex.
//   - pkg/hooks/messages plus messages.go/messages_*.go: centralized
//     user-facing ask/deny/fatal text so policy behavior and copy stay in sync.
//   - config_change.go, user_prompt.go, instructions.go, session_summary.go,
//     and session_end.go: non-tool lifecycle hooks that still run inside the
//     hooks package.
//   - pkg/posture/: posture hashing, managed hook subtree drift detection, and
//     restore-only tamper repair used by both hooks and cmd/sir.
//   - pkg/hooks/evidence, pkg/hooks/lifecycle, labels.go, credential_scan.go,
//     supply_chain.go, lineage.go, and evidence.go: supporting analyses reused
//     across the hook entry points.
//
// Start here when you need to change hook behavior without opening the whole
// package alphabetically. The matching *_test.go files lock in the invariants
// for each subsystem.
package hooks
