package runtime

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// DarwinHostControlSocketPaths returns unix-socket paths that grant control
// over the host or another security domain: container runtimes (root-
// equivalent via a privileged container), the SSH agent, and gpg-agent. The
// macOS sandbox allows unix sockets by default because many legitimate MCP
// servers XPC/IPC over them; these specific endpoints are denied in addition,
// matching the masking list Linux already applies.
//
// The list is static plus environment-derived. Paths that do not exist are
// harmless to deny, and including them keeps the generated profile stable
// across machines.
func DarwinHostControlSocketPaths() []string {
	cacheKey := os.Getenv("HOME") + "\x00" + os.Getenv("SSH_AUTH_SOCK")
	darwinSocketCache.mu.Lock()
	defer darwinSocketCache.mu.Unlock()
	if darwinSocketCache.key == cacheKey && darwinSocketCache.paths != nil {
		return darwinSocketCache.paths
	}
	paths := computeDarwinHostControlSocketPaths()
	darwinSocketCache.key = cacheKey
	darwinSocketCache.paths = paths
	darwinSocketCache.rules = ""
	return paths
}

var darwinSocketCache struct {
	mu    sync.Mutex
	key   string
	paths []string
	rules string
}

func computeDarwinHostControlSocketPaths() []string {
	seen := map[string]struct{}{}
	var paths []string
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || !filepath.IsAbs(path) {
			return
		}
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}

	add(os.Getenv("SSH_AUTH_SOCK"))
	if home, err := os.UserHomeDir(); err == nil {
		for _, rel := range []string{
			".docker/run/docker.sock",
			".docker/desktop/docker.sock",
			".colima/default/docker.sock",
			".colima/docker.sock",
			".podman/podman.sock",
			".local/share/containers/podman/machine/podman.sock",
			".gnupg/S.gpg-agent",
			".gnupg/S.gpg-agent.ssh",
		} {
			add(filepath.Join(home, rel))
		}
		if matches, err := filepath.Glob(filepath.Join(home, ".colima", "*", "docker.sock")); err == nil {
			for _, match := range matches {
				add(match)
			}
		}
	}
	for _, path := range []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/private/var/run/docker.sock",
		"/var/run/podman/podman.sock",
		"/run/podman/podman.sock",
		"/var/run/containerd/containerd.sock",
		"/run/containerd/containerd.sock",
		"/var/run/crio/crio.sock",
		"/run/crio/crio.sock",
		"/var/run/buildkit/buildkitd.sock",
		"/run/buildkit/buildkitd.sock",
	} {
		add(path)
	}

	sort.Strings(paths)
	return paths
}

// DarwinHostControlSocketDenyRules renders the deny rules for the macOS
// sandbox profile. sandbox-exec applies last-match-wins, so these must be
// emitted after the blanket unix-socket allow.
func DarwinHostControlSocketDenyRules() string {
	cacheKey := os.Getenv("HOME") + "\x00" + os.Getenv("SSH_AUTH_SOCK")
	darwinSocketCache.mu.Lock()
	defer darwinSocketCache.mu.Unlock()
	if darwinSocketCache.key == cacheKey && darwinSocketCache.rules != "" {
		return darwinSocketCache.rules
	}
	paths := darwinHostControlSocketPathsLocked(cacheKey)
	var rules strings.Builder
	for _, path := range paths {
		rules.WriteString("(deny network-outbound (remote unix-socket (path-literal \"")
		rules.WriteString(path)
		rules.WriteString("\")))\n")
	}
	darwinSocketCache.rules = rules.String()
	return darwinSocketCache.rules
}

// darwinHostControlSocketPathsLocked fills the cache while the caller holds
// darwinSocketCache.mu (or is the sole initializer).
func darwinHostControlSocketPathsLocked(cacheKey string) []string {
	if darwinSocketCache.key != cacheKey || darwinSocketCache.paths == nil {
		darwinSocketCache.key = cacheKey
		darwinSocketCache.paths = computeDarwinHostControlSocketPaths()
	}
	return darwinSocketCache.paths
}
