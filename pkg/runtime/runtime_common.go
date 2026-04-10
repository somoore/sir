package runtime

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func startRuntimeHeartbeat(projectRoot string) func() {
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := session.TouchRuntimeContainment(projectRoot, time.Now()); err != nil && !os.IsNotExist(err) {
					fmt.Fprintf(os.Stderr, "sir: run: runtime heartbeat error: %v\n", err)
				}
			case <-done:
				return
			}
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

// ClassifyWrappedAgentExit turns an exec.ExitError into an exit code.
func ClassifyWrappedAgentExit(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode(), nil
	}
	return 0, err
}

// SeedShadowState creates a shadow sir state tree for a contained launch.
func SeedShadowState(projectRoot, stateHome string) error {
	shadowDir := session.StateDirUnder(stateHome, projectRoot)
	if err := os.MkdirAll(shadowDir, 0o700); err != nil {
		return err
	}

	durableDir := session.DurableStateDir(projectRoot)
	for _, name := range []string{"lease.json", "session.json"} {
		srcPath := filepath.Join(durableDir, name)
		dstPath := filepath.Join(shadowDir, name)
		data, err := os.ReadFile(srcPath)
		if err != nil {
			if os.IsNotExist(err) {
				if name == "lease.json" {
					defaultLease, marshalErr := json.MarshalIndent(lease.DefaultLease(), "", "  ")
					if marshalErr != nil {
						return marshalErr
					}
					data = defaultLease
				} else {
					continue
				}
			} else {
				return err
			}
		}
		if err := os.WriteFile(dstPath, data, 0o600); err != nil {
			return err
		}
	}
	return nil
}
