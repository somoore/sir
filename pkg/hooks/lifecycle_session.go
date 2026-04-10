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
