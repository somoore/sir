package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// RuntimePath returns the durable runtime-containment status file path.
func RuntimePath(projectRoot string) string {
	return filepath.Join(DurableStateDir(projectRoot), "runtime.json")
}

// RuntimeLastPath returns the durable completed-runtime receipt path.
func RuntimeLastPath(projectRoot string) string {
	return filepath.Join(DurableStateDir(projectRoot), "runtime-last.json")
}

func saveRuntimeContainment(path string, info *RuntimeContainment) error {
	if info == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(path, data, 0o600)
}

func loadRuntimeContainment(path string) (*RuntimeContainment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var info RuntimeContainment
	if err := json.Unmarshal(data, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// SaveRuntimeContainment persists the active runtime-containment descriptor.
func SaveRuntimeContainment(projectRoot string, info *RuntimeContainment) error {
	return saveRuntimeContainment(RuntimePath(projectRoot), info)
}

// LoadRuntimeContainment reads the active runtime-containment descriptor.
func LoadRuntimeContainment(projectRoot string) (*RuntimeContainment, error) {
	return loadRuntimeContainment(RuntimePath(projectRoot))
}

// SaveLastRuntimeContainment persists the most recent completed runtime receipt.
func SaveLastRuntimeContainment(projectRoot string, info *RuntimeContainment) error {
	return saveRuntimeContainment(RuntimeLastPath(projectRoot), info)
}

// LoadLastRuntimeContainment reads the most recent completed runtime receipt.
func LoadLastRuntimeContainment(projectRoot string) (*RuntimeContainment, error) {
	return loadRuntimeContainment(RuntimeLastPath(projectRoot))
}

// RemoveRuntimeContainment removes the runtime-containment descriptor.
func RemoveRuntimeContainment(projectRoot string) error {
	err := os.Remove(RuntimePath(projectRoot))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// TouchRuntimeContainment refreshes the liveness heartbeat in the durable
// runtime descriptor without changing the rest of the recorded launch context.
func TouchRuntimeContainment(projectRoot string, now time.Time) error {
	info, err := LoadRuntimeContainment(projectRoot)
	if err != nil {
		return err
	}
	info.HeartbeatAt = now
	return SaveRuntimeContainment(projectRoot, info)
}
