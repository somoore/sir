package hooks

import (
	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
)

// detectSensitiveFileRead checks whether cmd is a shell read-command invoked
// against a sensitive path. Returns (resolvedSensitivePath, true) on hit so
// the caller can populate Intent.Target with the actual file, or ("", false)
// if no sensitive positional is found.
func detectSensitiveFileRead(cmd string, l *lease.Lease) (string, bool) {
	return hookclassify.DetectSensitiveFileRead(cmd, l)
}
