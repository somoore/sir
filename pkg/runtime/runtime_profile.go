package runtime

import (
	"fmt"
	"strings"
)

// BuildDarwinProfile creates the sandbox-exec profile used by the macOS
// runtime launcher. The profile generation itself is platform-neutral so it
// stays available to cross-platform tests and benchmarks.
func BuildDarwinProfile(projectRoot string, opts Options) (string, error) {
	var profile strings.Builder
	profile.Grow(8 * 1024)
	profile.WriteString("(version 1)\n")
	profile.WriteString("(allow default)\n")
	profile.WriteString("(deny network-outbound)\n")
	profile.WriteString("(allow network-outbound (remote unix-socket))\n")
	profile.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	// Last-match-wins: deny host-control sockets after the blanket allow so
	// a contained process cannot pivot through docker.sock, ssh-agent, etc.
	profile.WriteString(DarwinHostControlSocketDenyRules())
	guards, err := runProtectedWriteGuards(projectRoot)
	if err != nil {
		return "", err
	}
	for _, path := range guards.subpaths {
		profile.WriteString(fmt.Sprintf("(deny file-write* (subpath %q))\n", path))
	}
	for _, path := range guards.literals {
		profile.WriteString(fmt.Sprintf("(deny file-write* (literal %q))\n", path))
	}
	return profile.String(), nil
}
