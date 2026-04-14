package hooks

import (
	hookslifecycle "github.com/somoore/sir/pkg/hooks/lifecycle"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func SessionStart(projectRoot string, l *lease.Lease) (*session.State, error) {
	return hookslifecycle.SessionStart(projectRoot, l)
}

func bootstrapSessionBaseline(projectRoot string) error {
	return hookslifecycle.BootstrapSessionBaseline(projectRoot, loadLease)
}

func SessionEnd(projectRoot string) error {
	return hookslifecycle.SessionEnd(projectRoot)
}

// RebaselineSummary mirrors hookslifecycle.RebaselineSummary so callers in the
// cmd/ layer do not have to import the lifecycle subpackage directly.
type RebaselineSummary = hookslifecycle.RebaselineSummary

// RebaselineAllProjects refreshes posture/lease/global-hook baselines across
// every ~/.sir/projects/* state directory. Called by `sir install` after it
// rewrites the host-agent hook files so sessions that were alive across the
// upgrade are not wedged into deny_all.
func RebaselineAllProjects() (RebaselineSummary, error) {
	return hookslifecycle.RebaselineAllProjects()
}
