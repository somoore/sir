package runtime

import (
	"fmt"
	goruntime "runtime"
)

// Launcher is the selected host-agent containment strategy for the current OS.
type Launcher struct {
	Mode   string
	Launch func(projectRoot, bin string, opts Options) (int, error)
}

// SelectLauncher returns the runtime containment strategy supported by the
// current platform.
func SelectLauncher() Launcher {
	switch goruntime.GOOS {
	case "darwin":
		return Launcher{
			Mode:   ContainmentModeDarwinProxy,
			Launch: runAgentDarwin,
		}
	case "linux":
		return Launcher{
			Mode:   ContainmentModeLinuxNamespace,
			Launch: runAgentLinux,
		}
	default:
		return Launcher{
			Mode: "unsupported",
			Launch: func(projectRoot, bin string, opts Options) (int, error) {
				return 0, fmt.Errorf("experimental host-agent containment currently supports macOS and Linux only; see ARCHITECTURE.md for the current platform contract")
			},
		}
	}
}
