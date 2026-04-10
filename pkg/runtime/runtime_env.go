package runtime

import "strings"

var containmentScrubEnvKeys = []string{
	"SSH_AUTH_SOCK",
	"SSH_AGENT_PID",
	"SSH_ASKPASS",
	"SUDO_ASKPASS",
	"DOCKER_HOST",
	"CONTAINER_HOST",
	"PODMAN_HOST",
	"BUILDKIT_HOST",
	"DBUS_SESSION_BUS_ADDRESS",
	"DBUS_STARTER_ADDRESS",
	"DBUS_STARTER_BUS_TYPE",
	"GPG_AGENT_INFO",
	"GIT_SSH_COMMAND",
}

// RunProxyEnv returns the proxy environment injected into the contained agent.
func RunProxyEnv(httpProxyURL, socksProxyURL string) map[string]string {
	noProxy := strings.Join([]string{"localhost", "127.0.0.1", "::1"}, ",")
	if socksProxyURL == "" {
		socksProxyURL = httpProxyURL
	}
	return map[string]string{
		"HTTP_PROXY":  httpProxyURL,
		"HTTPS_PROXY": httpProxyURL,
		"ALL_PROXY":   socksProxyURL,
		"NO_PROXY":    noProxy,
		"http_proxy":  httpProxyURL,
		"https_proxy": httpProxyURL,
		"all_proxy":   socksProxyURL,
		"no_proxy":    noProxy,
	}
}

// WithEnvOverride replaces or appends one environment variable entry.
func WithEnvOverride(base []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, entry := range base {
		if strings.HasPrefix(entry, prefix) {
			continue
		}
		out = append(out, entry)
	}
	return append(out, prefix+value)
}

func sanitizeContainmentEnv(base []string) ([]string, []string) {
	out := append([]string(nil), base...)
	scrubbed := make([]string, 0, len(containmentScrubEnvKeys))
	for _, key := range containmentScrubEnvKeys {
		var removed bool
		out, removed = removeEnvKey(out, key)
		if removed {
			scrubbed = append(scrubbed, key)
		}
	}
	return out, scrubbed
}

func removeEnvKey(base []string, key string) ([]string, bool) {
	prefix := key + "="
	out := make([]string, 0, len(base))
	removed := false
	for _, entry := range base {
		if strings.HasPrefix(entry, prefix) {
			removed = true
			continue
		}
		out = append(out, entry)
	}
	return out, removed
}
