package runtime

import (
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func linuxHostControlSockets() []string {
	seen := map[string]struct{}{}
	sockets := make([]string, 0, 12)
	add := func(path string) {
		path = normalizeUnixSocketPath(path)
		if path == "" {
			return
		}
		if _, err := os.Lstat(path); err != nil {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		sockets = append(sockets, path)
	}

	add(os.Getenv("SSH_AUTH_SOCK"))
	add(dbusSocketFromAddress(os.Getenv("DBUS_SESSION_BUS_ADDRESS")))
	for _, value := range []string{
		os.Getenv("DOCKER_HOST"),
		os.Getenv("CONTAINER_HOST"),
		os.Getenv("PODMAN_HOST"),
		os.Getenv("BUILDKIT_HOST"),
	} {
		add(unixSocketFromEndpoint(value))
	}

	if xdgRuntime := normalizeUnixSocketPath(os.Getenv("XDG_RUNTIME_DIR")); xdgRuntime != "" {
		add(filepath.Join(xdgRuntime, "bus"))
		for _, rel := range []string{
			"docker.sock",
			filepath.Join("podman", "podman.sock"),
			"buildkitd.sock",
			filepath.Join("buildkit", "buildkitd.sock"),
		} {
			add(filepath.Join(xdgRuntime, rel))
		}
	}
	for _, path := range gpgAgentSocketCandidates() {
		add(path)
	}

	for _, path := range []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
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

	sort.Strings(sockets)
	return sockets
}

func normalizeUnixSocketPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return ""
	}
	return filepath.Clean(path)
}

func unixSocketFromEndpoint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "unix://") {
		if parsed, err := url.Parse(raw); err == nil {
			return normalizeUnixSocketPath(parsed.Path)
		}
	}
	return normalizeUnixSocketPath(raw)
}

func dbusSocketFromAddress(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "unix:") {
		return ""
	}
	raw = strings.TrimPrefix(raw, "unix:")
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "path=") {
			return normalizeUnixSocketPath(strings.TrimPrefix(part, "path="))
		}
	}
	return ""
}

func gpgAgentSocketCandidates() []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 8)
	addDir := func(dir string) {
		dir = normalizeUnixSocketPath(dir)
		if dir == "" {
			return
		}
		for _, name := range []string{
			"S.gpg-agent",
			"S.gpg-agent.browser",
			"S.gpg-agent.extra",
			"S.gpg-agent.ssh",
		} {
			path := filepath.Join(dir, name)
			if _, ok := seen[path]; ok {
				continue
			}
			seen[path] = struct{}{}
			out = append(out, path)
		}
	}

	addDir(os.Getenv("GNUPGHOME"))
	if home, err := os.UserHomeDir(); err == nil {
		addDir(filepath.Join(home, ".gnupg"))
	}
	if xdgRuntime := normalizeUnixSocketPath(os.Getenv("XDG_RUNTIME_DIR")); xdgRuntime != "" {
		addDir(filepath.Join(xdgRuntime, "gnupg"))
	}
	return out
}
