package runtime

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func runAgentLinux(projectRoot, bin string, opts Options) (int, error) {
	if len(opts.AllowedHosts) > 0 {
		return runAgentLinuxAllowlist(projectRoot, bin, opts)
	}
	return runAgentLinuxOffline(projectRoot, bin, opts)
}

func runAgentLinuxOffline(projectRoot, bin string, opts Options) (int, error) {
	if err := ensureLinuxContainmentBinary("unshare"); err != nil {
		return 0, err
	}
	if err := ensureLinuxContainmentBinary("mount"); err != nil {
		return 0, err
	}
	stateHome, err := os.MkdirTemp("", "sir-run-state-*")
	if err != nil {
		return 0, fmt.Errorf("create shadow state home: %w", err)
	}
	defer os.RemoveAll(stateHome)
	if err := SeedShadowState(projectRoot, stateHome); err != nil {
		return 0, fmt.Errorf("seed shadow state: %w", err)
	}

	maskedSockets := linuxHostControlSockets()
	script, err := linuxContainmentAllowlistScript(projectRoot, opts.Agent, linuxAllowlistBootstrap{
		MaskedSockets: maskedSockets,
	})
	if err != nil {
		return 0, fmt.Errorf("build linux containment bootstrap: %w", err)
	}
	unshareArgs := []string{
		"--user",
		"--map-root-user",
		"--net",
		"--mount",
		"--mount-proc",
		"/bin/sh",
		"-c",
		script,
		"sh",
		bin,
	}
	unshareArgs = append(unshareArgs, opts.Passthrough...)

	cmd := exec.Command("unshare", unshareArgs...)
	baseEnv, scrubbedEnv := sanitizeContainmentEnv(os.Environ())
	cmd.Env = WithEnvOverride(baseEnv, session.StateHomeEnvVar, stateHome)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Fprintln(os.Stderr, "sir: run: experimental containment (Linux network namespace with outbound egress denied)")
	fmt.Fprintln(os.Stderr, "sir: run: no external network is available inside this containment mode")
	if len(maskedSockets) > 0 {
		fmt.Fprintf(os.Stderr, "sir: run: masked host control sockets: %s\n", strings.Join(maskedSockets, ", "))
	}
	if len(scrubbedEnv) > 0 {
		fmt.Fprintf(os.Stderr, "sir: run: scrubbed host-control env: %s\n", strings.Join(scrubbedEnv, ", "))
	}
	fmt.Fprintln(os.Stderr, "sir: run: write-deny list protects the current agent's real hook config, canonical backups, durable sir state, and shared posture files; general workspace writes remain allowed once those guarded paths exist")

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	runtimeInfo := &session.RuntimeContainment{
		AgentID:                 string(opts.Agent.ID()),
		Mode:                    ContainmentModeLinuxNamespace,
		AllowedHostCount:        0,
		AllowedDestinationCount: 0,
		MaskedHostSockets:       append([]string(nil), maskedSockets...),
		ScrubbedEnvVars:         append([]string(nil), scrubbedEnv...),
		ShadowStateHome:         stateHome,
		StartedAt:               time.Now(),
		HeartbeatAt:             time.Now(),
		LauncherPID:             os.Getpid(),
		AgentPID:                cmd.Process.Pid,
	}
	if err := persistRuntimeContainment(projectRoot, runtimeInfo, cmd); err != nil {
		return 0, err
	}

	stopHeartbeat := startRuntimeHeartbeat(projectRoot)
	defer stopHeartbeat()

	exitCode, err := ClassifyWrappedAgentExit(cmd.Wait())
	if err != nil {
		return 0, err
	}
	if err := finalizeRuntimeContainment(projectRoot, runtimeInfo, exitCode); err != nil {
		return 0, err
	}
	return exitCode, nil
}

func runAgentLinuxAllowlist(projectRoot, bin string, opts Options) (int, error) {
	for _, name := range []string{"unshare", "mount", "slirp4netns", "iptables"} {
		if err := ensureLinuxContainmentBinary(name); err != nil {
			return 0, err
		}
	}

	stateHome, err := os.MkdirTemp("", "sir-run-state-*")
	if err != nil {
		return 0, fmt.Errorf("create shadow state home: %w", err)
	}
	defer os.RemoveAll(stateHome)
	if err := SeedShadowState(projectRoot, stateHome); err != nil {
		return 0, fmt.Errorf("seed shadow state: %w", err)
	}

	allowlist, err := buildRuntimeAllowlistForProject(projectRoot, opts)
	if err != nil {
		return 0, fmt.Errorf("load runtime allowlist: %w", err)
	}
	resolved, err := resolveRuntimeDestinations(allowlist, net.DefaultResolver.LookupHost)
	if err != nil {
		return 0, fmt.Errorf("resolve runtime allowlist: %w", err)
	}
	if err := ensureLinuxIPv6Filtering(resolved); err != nil {
		return 0, err
	}

	syncDir, err := os.MkdirTemp("", "sir-run-linux-sync-*")
	if err != nil {
		return 0, fmt.Errorf("create linux containment sync dir: %w", err)
	}
	defer os.RemoveAll(syncDir)
	pidFile := syncDir + "/child.pid"
	readyFile := syncDir + "/ready"

	maskedSockets := linuxHostControlSockets()
	script, err := linuxContainmentAllowlistScript(projectRoot, opts.Agent, linuxAllowlistBootstrap{
		PIDFile:       pidFile,
		ReadyFile:     readyFile,
		Resolved:      resolved,
		HostsLines:    linuxHostsLines(resolved),
		MaskedSockets: maskedSockets,
	})
	if err != nil {
		return 0, fmt.Errorf("build linux containment bootstrap: %w", err)
	}
	unshareArgs := []string{
		"--fork",
		"--user",
		"--map-root-user",
		"--net",
		"--mount",
		"--mount-proc",
		"/bin/sh",
		"-c",
		script,
		"sh",
		bin,
	}
	unshareArgs = append(unshareArgs, opts.Passthrough...)

	cmd := exec.Command("unshare", unshareArgs...)
	baseEnv, scrubbedEnv := sanitizeContainmentEnv(os.Environ())
	cmd.Env = WithEnvOverride(baseEnv, session.StateHomeEnvVar, stateHome)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	childPID, err := waitForLinuxNamespacePID(pidFile, 2*time.Second)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("discover linux containment child pid: %w", err)
	}

	slirp := exec.Command("slirp4netns", "--configure", "--disable-host-loopback", strconv.Itoa(childPID), "tap0")
	slirp.Stdout = os.Stderr
	slirp.Stderr = os.Stderr
	if err := slirp.Start(); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("start linux user-mode network: %w", err)
	}
	defer func() {
		if slirp.Process != nil {
			_ = slirp.Process.Kill()
			_, _ = slirp.Process.Wait()
		}
	}()

	if err := os.WriteFile(readyFile, []byte("ready\n"), 0o600); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, fmt.Errorf("signal linux containment readiness: %w", err)
	}

	allowedHosts := allowlist.Hosts()
	allowedDestinations := allowlist.Destinations()
	fmt.Fprintln(os.Stderr, "sir: run: experimental containment (Linux namespace + exact-destination egress allowlist)")
	fmt.Fprintln(os.Stderr, "sir: run: proxy independence: direct outbound sockets are still denied unless they match the exact destination policy")
	fmt.Fprintf(os.Stderr, "sir: run: allowlisted hosts: %s\n", strings.Join(allowedHosts, ", "))
	fmt.Fprintf(os.Stderr, "sir: run: exact destinations: %s\n", strings.Join(allowedDestinations, ", "))
	if len(maskedSockets) > 0 {
		fmt.Fprintf(os.Stderr, "sir: run: masked host control sockets: %s\n", strings.Join(maskedSockets, ", "))
	}
	if len(scrubbedEnv) > 0 {
		fmt.Fprintf(os.Stderr, "sir: run: scrubbed host-control env: %s\n", strings.Join(scrubbedEnv, ", "))
	}
	fmt.Fprintln(os.Stderr, "sir: run: write-deny list protects the current agent's real hook config, canonical backups, durable sir state, and shared posture files; general workspace writes remain allowed once those guarded paths exist")

	runtimeInfo := &session.RuntimeContainment{
		AgentID:                 string(opts.Agent.ID()),
		Mode:                    ContainmentModeLinuxAllowlist,
		AllowedHosts:            append([]string(nil), allowedHosts...),
		AllowedDestinations:     append([]string(nil), allowedDestinations...),
		AllowedHostCount:        len(allowedHosts),
		AllowedDestinationCount: len(allowedDestinations),
		MaskedHostSockets:       append([]string(nil), maskedSockets...),
		ScrubbedEnvVars:         append([]string(nil), scrubbedEnv...),
		ShadowStateHome:         stateHome,
		StartedAt:               time.Now(),
		HeartbeatAt:             time.Now(),
		LauncherPID:             os.Getpid(),
		AgentPID:                childPID,
	}
	if err := persistRuntimeContainment(projectRoot, runtimeInfo, cmd); err != nil {
		return 0, err
	}

	stopHeartbeat := startRuntimeHeartbeat(projectRoot)
	defer stopHeartbeat()

	exitCode, err := ClassifyWrappedAgentExit(cmd.Wait())
	if err != nil {
		return 0, err
	}
	if err := finalizeRuntimeContainment(projectRoot, runtimeInfo, exitCode); err != nil {
		return 0, err
	}
	return exitCode, nil
}
