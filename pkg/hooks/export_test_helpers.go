package hooks

import (
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// ExportEvaluatePayload exposes evaluatePayload for integration tests.
func ExportEvaluatePayload(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, error) {
	return evaluatePayload(payload, l, state, projectRoot)
}

// ExportPostEvaluatePayload exposes postEvaluatePayload for integration tests.
func ExportPostEvaluatePayload(payload *PostHookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, error) {
	return postEvaluatePayload(payload, l, state, projectRoot)
}
