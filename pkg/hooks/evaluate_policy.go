package hooks

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func evaluatePolicy(projectRoot string, payload *HookPayload, intent Intent, l *lease.Lease, state *session.State, labels core.Label) (*core.Response, error) {
	req, err := buildCoreRequest(projectRoot, payload, intent, l, state, labels)
	if err != nil {
		return nil, fmt.Errorf("build core request: %w", err)
	}
	if _, lookErr := exec.LookPath(core.CoreBinaryPath); lookErr != nil {
		fmt.Fprintf(os.Stderr, "sir WARNING: mister-core binary not found — using Go fallback. Policy enforcement is degraded. Reinstall sir to restore full protection.\n")
	}
	coreResp, err := core.Evaluate(req)
	if err != nil {
		return nil, fmt.Errorf("core evaluate: %w", err)
	}
	return coreResp, nil
}
