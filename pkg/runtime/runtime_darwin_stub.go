//go:build !darwin

package runtime

import "fmt"

func runAgentDarwin(projectRoot, bin string, opts Options) (int, error) {
	return 0, fmt.Errorf("experimental host-agent containment currently supports sandbox-exec on macOS only")
}
