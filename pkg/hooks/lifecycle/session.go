package lifecycle

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func SessionStart(projectRoot string, l *lease.Lease) (*session.State, error) {
	state := session.NewState(projectRoot)
	policy, err := session.LoadManagedPolicy()
	if err != nil {
		return nil, fmt.Errorf("load managed policy: %w", err)
	}

	if err := protectStateDirectory(projectRoot); err != nil {
		return nil, fmt.Errorf("protect state dir: %w", err)
	}

	state.PostureHashes = posture.HashSentinelFiles(projectRoot, l.PostureFiles)
	if policy != nil {
		state.LeaseHash = policy.ManagedLeaseHash
	} else if leaseHash, err := posture.HashLeaseFile(projectRoot); err == nil {
		state.LeaseHash = leaseHash
	}
	if policy != nil {
		if globalHash, ok, err := posture.ManagedGlobalHooksHash(); err == nil && ok {
			state.GlobalHookHash = globalHash
		}
	} else if globalHash, err := posture.HashGlobalHooksFile(); err == nil {
		state.GlobalHookHash = globalHash
	}
	if err := state.Save(); err != nil {
		return nil, err
	}

	return state, nil
}

func BootstrapSessionBaseline(projectRoot string, loadLease func(string) (*lease.Lease, error)) error {
	l, err := loadLease(projectRoot)
	if err != nil || l == nil {
		return fmt.Errorf("load lease for baseline: %w", err)
	}
	policy, err := session.LoadManagedPolicy()
	if err != nil {
		return fmt.Errorf("load managed policy for baseline: %w", err)
	}
	return session.WithSessionLock(projectRoot, func() error {
		if existing, loadErr := session.Load(projectRoot); loadErr == nil && existing != nil {
			return nil
		} else if loadErr != nil && !os.IsNotExist(loadErr) {
			return fmt.Errorf("load existing session for baseline: %w", loadErr)
		}
		st := session.NewState(projectRoot)
		st.PostureHashes = posture.HashSentinelFiles(projectRoot, l.PostureFiles)
		if policy != nil {
			st.LeaseHash = policy.ManagedLeaseHash
		} else if leaseHash, hashErr := posture.HashLeaseFile(projectRoot); hashErr == nil {
			st.LeaseHash = leaseHash
		}
		if policy != nil {
			if globalHash, ok, hashErr := posture.ManagedGlobalHooksHash(); hashErr == nil && ok {
				st.GlobalHookHash = globalHash
			}
		} else if globalHash, hashErr := posture.HashGlobalHooksFile(); hashErr == nil {
			st.GlobalHookHash = globalHash
		}
		return st.Save()
	})
}

func SessionEnd(projectRoot string) error {
	state, err := session.Load(projectRoot)
	if err != nil {
		return err
	}
	return state.Save()
}

func protectStateDirectory(projectRoot string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sirDir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(sirDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(sirDir, 0o700); err != nil {
		return err
	}

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(stateDir, 0o700); err != nil {
		return err
	}

	entries, err := os.ReadDir(stateDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fpath := filepath.Join(stateDir, e.Name())
		if chErr := os.Chmod(fpath, 0o600); chErr != nil {
			return chErr
		}
	}

	return nil
}
