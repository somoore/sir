package hooks

import (
	hookslifecycle "github.com/somoore/sir/pkg/hooks/lifecycle"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// loadOptionalLifecycleSession returns nil,nil when the project has no
// session yet, but treats corruption, permission failures, and other I/O
// errors as real hook errors so lifecycle handlers do not silently skip
// security checks on unreadable state.
func loadOptionalLifecycleSession(projectRoot, hookName string) (*session.State, error) {
	return hookslifecycle.LoadOptionalSession(projectRoot, hookName)
}

// loadLifecycleLease reuses the main hook-path lease loader so lifecycle
// handlers get the same managed-policy and missing-file semantics as
// PreToolUse. Unreadable lease state is surfaced as a hard error.
func loadLifecycleLease(projectRoot, hookName string) (*lease.Lease, error) {
	return hookslifecycle.LoadLease(projectRoot, hookName, loadLease)
}
