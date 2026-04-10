package session

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// StateHomeEnvVar overrides the home directory prefix used for sir's per-project
// state. This is reserved for controlled launchers such as `sir run`; normal
// installs should rely on os.UserHomeDir().
const StateHomeEnvVar = "SIR_STATE_HOME"

// ProjectHash returns the SHA-256 hex digest of the project root path,
// used as the directory name under ~/.sir/projects/.
func ProjectHash(projectRoot string) string {
	h := sha256.Sum256([]byte(projectRoot))
	return fmt.Sprintf("%x", h)
}

// StateDirUnder returns the path to the sir state directory for a project
// rooted under the provided home directory.
func StateDirUnder(home, projectRoot string) string {
	return filepath.Join(home, ".sir", "projects", ProjectHash(projectRoot))
}

// DurableStateDir returns the long-lived per-project state path under the real
// user home directory, ignoring any session-local override such as SIR_STATE_HOME.
func DurableStateDir(projectRoot string) string {
	home, _ := os.UserHomeDir()
	return StateDirUnder(home, projectRoot)
}

// StateDir returns the path to the sir state directory for a project.
func StateDir(projectRoot string) string {
	home := strings.TrimSpace(os.Getenv(StateHomeEnvVar))
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return StateDirUnder(home, projectRoot)
}

// StatePath returns the path to the session state file.
func StatePath(projectRoot string) string {
	return filepath.Join(StateDir(projectRoot), "session.json")
}
