package runtime

import (
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func persistRuntimeContainment(projectRoot string, info *session.RuntimeContainment, cmd *exec.Cmd) error {
	if info == nil {
		return fmt.Errorf("runtime containment descriptor missing")
	}
	info.DegradedReasons = info.EffectiveDegradedReasons()
	if err := session.SaveRuntimeContainment(projectRoot, info); err != nil {
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		return fmt.Errorf("write runtime status: %w", err)
	}
	return nil
}

func finalizeRuntimeContainment(projectRoot string, info *session.RuntimeContainment, exitCode int) error {
	if info == nil {
		return session.RemoveRuntimeContainment(projectRoot)
	}
	info.ExitCode = exitCode
	info.EndedAt = time.Now()

	var joined error
	if err := session.SaveLastRuntimeContainment(projectRoot, info); err != nil {
		joined = errors.Join(joined, fmt.Errorf("write runtime receipt: %w", err))
	}
	if err := session.RemoveRuntimeContainment(projectRoot); err != nil {
		joined = errors.Join(joined, fmt.Errorf("remove active runtime state: %w", err))
	}
	return joined
}

func applyProxyReceipt(info *session.RuntimeContainment, proxy *LocalProxy) {
	if info == nil || proxy == nil {
		return
	}
	stats := proxy.snapshotStats()
	info.AllowedEgressCount = stats.allowedEgressCount
	info.BlockedEgressCount = stats.blockedEgressCount
	info.LastBlockedDestination = stats.lastBlockedDest
}
