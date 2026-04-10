package session

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PruneStaleRuntimeContainment removes stale runtime metadata and any safe
// shadow-state directory created by an earlier `sir run` launch.
func PruneStaleRuntimeContainment(projectRoot string, now time.Time) error {
	inspection, err := InspectRuntimeContainment(projectRoot, now)
	if err != nil || inspection == nil || inspection.Health != RuntimeContainmentStale {
		return err
	}
	if inspection.Reason == "runtime heartbeat expired" && runtimeProcessAlive(inspection.Info) {
		return nil
	}
	var joined error
	if inspection.Info != nil && isManagedShadowStatePath(inspection.Info.ShadowStateHome) {
		if err := os.RemoveAll(inspection.Info.ShadowStateHome); err != nil {
			joined = errors.Join(joined, err)
		}
	}
	if err := RemoveRuntimeContainment(projectRoot); err != nil {
		joined = errors.Join(joined, err)
	}
	return joined
}

func isManagedShadowStatePath(path string) bool {
	clean := filepath.Clean(strings.TrimSpace(path))
	if clean == "." || clean == "" {
		return false
	}
	if filepath.Base(clean) == "." || !strings.HasPrefix(filepath.Base(clean), "sir-run-state-") {
		return false
	}
	tempRoot := filepath.Clean(os.TempDir())
	return clean == tempRoot || strings.HasPrefix(clean, tempRoot+string(os.PathSeparator))
}

func runtimeProcessAlive(info *RuntimeContainment) bool {
	if info == nil {
		return false
	}
	return pidAlive(info.AgentPID) || pidAlive(info.LauncherPID)
}
