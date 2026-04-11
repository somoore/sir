package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/agent"
)

type linuxAllowlistBootstrap struct {
	PIDFile       string
	ReadyFile     string
	Resolved      []linuxResolvedDestination
	HostsLines    []string
	MaskedSockets []string
}

func linuxContainmentAllowlistScript(projectRoot string, ag agent.Agent, setup linuxAllowlistBootstrap) (string, error) {
	guards, err := runProtectedWriteGuardsForAgent(projectRoot, ag)
	if err != nil {
		return "", err
	}
	if missing := linuxMissingGuardTargets(guards); len(missing) > 0 {
		return "", fmt.Errorf("linux host-agent containment requires pre-existing protected paths before launch: %s", strings.Join(missing, ", "))
	}

	lines := []string{"set -eu"}
	if setup.PIDFile != "" {
		lines = append(lines,
			"# Capture the host-visible PID even when the child becomes pid 1 inside a nested pid namespace.",
			"ns_host_pid=$(awk '/^NSpid:/ {print $2; exit}' /proc/self/status 2>/dev/null || true)",
			"if [ -z \"$ns_host_pid\" ]; then ns_host_pid=$$; fi",
			fmt.Sprintf("echo \"$ns_host_pid\" > %s", shellQuote(setup.PIDFile)),
			fmt.Sprintf("while [ ! -f %s ]; do sleep 0.05; done", shellQuote(setup.ReadyFile)),
			fmt.Sprintf("rm -f %s", shellQuote(setup.ReadyFile)),
		)
	}
	lines = append(lines,
		"mount --make-rprivate /",
		"bind_readonly() {",
		"  path=\"$1\"",
		"  if [ ! -e \"$path\" ]; then",
		"    return 0",
		"  fi",
		"  if [ -d \"$path\" ]; then",
		"    mount --rbind \"$path\" \"$path\"",
		"  else",
		"    mount --bind \"$path\" \"$path\"",
		"  fi",
		"  mount -o remount,bind,ro \"$path\" >/dev/null 2>&1 || mount -o remount,ro,bind \"$path\"",
		"}",
	)
	if len(setup.MaskedSockets) > 0 {
		lines = append(lines, linuxHostSocketMaskBootstrapLines()...)
	}
	for _, path := range guards.subpaths {
		lines = append(lines, fmt.Sprintf("bind_readonly %s", shellQuote(path)))
	}
	for _, path := range guards.literals {
		lines = append(lines, fmt.Sprintf("bind_readonly %s", shellQuote(path)))
	}
	for _, path := range setup.MaskedSockets {
		lines = append(lines, fmt.Sprintf("mask_runtime_socket %s", shellQuote(path)))
	}
	lines = append(lines, linuxLoopbackBootstrapLines()...)
	if len(setup.HostsLines) > 0 {
		lines = append(lines, linuxHostsOverrideBootstrapLines(setup.HostsLines)...)
	}
	if len(setup.Resolved) > 0 {
		ipv4Destinations, ipv6Destinations := splitLinuxResolvedDestinations(setup.Resolved)
		if len(ipv4Destinations) > 0 {
			lines = append(lines,
				"iptables -P OUTPUT DROP",
				"iptables -A OUTPUT -o lo -j ACCEPT",
			)
			for _, dest := range ipv4Destinations {
				lines = append(lines, fmt.Sprintf("iptables -A OUTPUT -p tcp -d %s --dport %s -j ACCEPT", shellQuote(dest.IP), shellQuote(dest.Port)))
			}
		}
		lines = append(lines,
			"if command -v ip6tables >/dev/null 2>&1; then",
			"  ip6tables -P OUTPUT DROP >/dev/null 2>&1 || true",
			"  ip6tables -A OUTPUT -o lo -j ACCEPT >/dev/null 2>&1 || true",
		)
		for _, dest := range ipv6Destinations {
			lines = append(lines, fmt.Sprintf("  ip6tables -A OUTPUT -p tcp -d %s --dport %s -j ACCEPT >/dev/null 2>&1 || true", shellQuote(dest.IP), shellQuote(dest.Port)))
		}
		lines = append(lines, "fi")
	}
	lines = append(lines, `exec "$@"`)
	return strings.Join(lines, "\n"), nil
}

func linuxContainmentBootstrapScript(projectRoot string, ag agent.Agent) (string, error) {
	return linuxContainmentAllowlistScript(projectRoot, ag, linuxAllowlistBootstrap{
		MaskedSockets: linuxHostControlSockets(),
	})
}

func linuxLoopbackBootstrapLines() []string {
	return []string{
		"if command -v ip >/dev/null 2>&1; then ip link set lo up >/dev/null 2>&1 || true; fi",
		"if command -v ifconfig >/dev/null 2>&1; then ifconfig lo up >/dev/null 2>&1 || true; fi",
	}
}

func linuxHostsOverrideBootstrapLines(hostsLines []string) []string {
	lines := []string{
		"hosts_override=$(mktemp /tmp/sir-hosts.XXXXXX)",
		"cp /etc/hosts \"$hosts_override\" >/dev/null 2>&1 || cat /etc/hosts > \"$hosts_override\"",
	}
	for _, line := range hostsLines {
		lines = append(lines, fmt.Sprintf("printf '%%s\\n' %s >> \"$hosts_override\"", shellQuote(line)))
	}
	lines = append(lines, "mount --bind \"$hosts_override\" /etc/hosts")
	return lines
}

func linuxHostSocketMaskBootstrapLines() []string {
	return []string{
		"sir_mask_root=$(mktemp -d /tmp/sir-mask.XXXXXX)",
		"mask_runtime_socket() {",
		"  path=\"$1\"",
		"  if [ ! -e \"$path\" ] || [ -d \"$path\" ]; then",
		"    return 0",
		"  fi",
		"  mask_file=\"$sir_mask_root/$(basename \"$path\").mask\"",
		"  : > \"$mask_file\"",
		"  mount --bind \"$mask_file\" \"$path\"",
		"  mount -o remount,bind,ro \"$path\" >/dev/null 2>&1 || mount -o remount,ro,bind \"$path\"",
		"}",
	}
}

func shellQuote(path string) string {
	return "'" + strings.ReplaceAll(filepath.Clean(path), "'", `'"'"'`) + "'"
}

func ensureLinuxContainmentBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("linux host-agent containment requires the `%s` binary on PATH", name)
	}
	return nil
}

func waitForLinuxNamespacePID(path string, timeout time.Duration) (int, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(data)))
			if convErr != nil {
				return 0, fmt.Errorf("parse child pid: %w", convErr)
			}
			if pid > 0 {
				return pid, nil
			}
		} else if !os.IsNotExist(err) {
			return 0, err
		}
		time.Sleep(25 * time.Millisecond)
	}
	return 0, fmt.Errorf("timed out waiting for linux containment child pid")
}

func linuxMissingGuardTargets(guards runWriteGuards) []string {
	existingSubpaths := make([]string, 0, len(guards.subpaths))
	missing := make([]string, 0)
	for _, path := range guards.subpaths {
		if runtimePathExists(path) {
			existingSubpaths = append(existingSubpaths, path)
			continue
		}
		missing = append(missing, path)
	}
	for _, path := range guards.literals {
		if runtimePathExists(path) || linuxCoveredBySubpath(path, existingSubpaths) {
			continue
		}
		missing = append(missing, path)
	}
	return missing
}

func runtimePathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func linuxCoveredBySubpath(path string, prefixes []string) bool {
	cleanPath := filepath.Clean(path)
	for _, prefix := range prefixes {
		cleanPrefix := filepath.Clean(prefix)
		if cleanPath == cleanPrefix || strings.HasPrefix(cleanPath, cleanPrefix+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
