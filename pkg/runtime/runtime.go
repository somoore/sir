package runtime

import (
	"fmt"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// Launch resolves the agent binary, selects the platform launcher, and starts
// the contained host agent.
func Launch(projectRoot string, opts Options) (int, error) {
	if opts.Agent == nil {
		return 0, fmt.Errorf("runtime launch requires a non-nil agent")
	}
	if err := session.PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
		return 0, fmt.Errorf("prune stale runtime state: %w", err)
	}
	bin, err := ResolveBinary(opts.Agent)
	if err != nil {
		return 0, err
	}
	launcher := SelectLauncher()
	exitCode, err := launcher.Launch(projectRoot, bin, opts)
	if err != nil {
		return 0, err
	}
	return exitCode, nil
}
