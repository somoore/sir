package lifecycle

import (
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

type LeaseLoader func(string) (*lease.Lease, error)

func LoadOptionalSession(projectRoot, hookName string) (*session.State, error) {
	state, err := session.Load(projectRoot)
	if err == nil {
		return state, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, fmt.Errorf("%s: load session: %w", hookName, err)
}

func LoadLease(projectRoot, hookName string, loader LeaseLoader) (*lease.Lease, error) {
	l, err := loader(projectRoot)
	if err != nil {
		return nil, fmt.Errorf("%s: load lease: %w", hookName, err)
	}
	return l, nil
}
