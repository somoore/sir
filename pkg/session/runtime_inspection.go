package session

import (
	"os"
	"strings"
	"time"
)

const runtimeContainmentHeartbeatGrace = 20 * time.Second

// InspectRuntimeContainment loads the durable runtime descriptor and classifies
// it as active or stale. A nil inspection with nil error means no runtime
// containment metadata is currently present.
func InspectRuntimeContainment(projectRoot string, now time.Time) (*RuntimeContainmentInspection, error) {
	info, err := LoadRuntimeContainment(projectRoot)
	if err != nil {
		if os.IsNotExist(err) {
			last, lastErr := LoadLastRuntimeContainment(projectRoot)
			if lastErr != nil {
				if os.IsNotExist(lastErr) {
					return nil, nil
				}
				return nil, lastErr
			}
			return &RuntimeContainmentInspection{
				Info:   last,
				Health: RuntimeContainmentInactive,
			}, nil
		}
		return nil, err
	}

	inspection := &RuntimeContainmentInspection{
		Info:   info,
		Health: RuntimeContainmentActive,
	}

	switch {
	case info.ShadowStateHome == "":
		inspection.Health = RuntimeContainmentStale
		inspection.Reason = "shadow state path missing"
	case !pathExists(info.ShadowStateHome):
		inspection.Health = RuntimeContainmentStale
		inspection.Reason = "shadow state directory missing"
	case info.HeartbeatAt.IsZero():
		inspection.Health = RuntimeContainmentLegacy
		inspection.Reason = "runtime heartbeat unavailable (legacy descriptor)"
	case now.Sub(info.HeartbeatAt) > runtimeContainmentHeartbeatGrace:
		inspection.Health = RuntimeContainmentStale
		inspection.Reason = "runtime heartbeat expired"
	case len(info.EffectiveDegradedReasons()) > 0:
		inspection.Health = RuntimeContainmentDegraded
		inspection.Reason = strings.Join(info.EffectiveDegradedReasons(), "; ")
	}

	return inspection, nil
}

func pathExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
