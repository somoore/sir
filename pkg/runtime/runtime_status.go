package runtime

import (
	"fmt"
	"os/exec"

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
