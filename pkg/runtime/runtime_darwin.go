package runtime

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func runAgentDarwin(projectRoot, bin string, opts Options) (int, error) {
	profile, err := BuildDarwinProfile(projectRoot, opts)
	if err != nil {
		return 0, fmt.Errorf("build sandbox profile: %w", err)
	}
	tmpFile, err := os.CreateTemp("", "sir-run-*.sb")
	if err != nil {
		return 0, fmt.Errorf("create sandbox profile: %w", err)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(profile); err != nil {
		return 0, fmt.Errorf("write sandbox profile: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return 0, fmt.Errorf("close sandbox profile: %w", err)
	}

	sandboxArgs := []string{"-f", tmpFile.Name(), bin}
	sandboxArgs = append(sandboxArgs, opts.Passthrough...)

	cmd := exec.Command("sandbox-exec", sandboxArgs...)
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
		return 0, fmt.Errorf("load proxy host policy: %w", err)
	}
	allowedHosts := allowlist.Hosts()
	allowedDestinations := allowlist.Destinations()
	proxy, err := startLocalProxyWithAllowlist(allowlist, net.DefaultResolver.LookupHost)
	if err != nil {
		return 0, fmt.Errorf("start local proxy: %w", err)
	}
	defer proxy.Close()

	baseEnv, scrubbedEnv := sanitizeContainmentEnv(os.Environ())
	cmd.Env = WithEnvOverride(baseEnv, session.StateHomeEnvVar, stateHome)
	for key, value := range RunProxyEnv(proxy.URL(), proxy.SOCKSURL()) {
		cmd.Env = WithEnvOverride(cmd.Env, key, value)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Fprintln(os.Stderr, "sir: run: experimental containment (macOS localhost-only sandbox + provider-aware local proxy)")
	fmt.Fprintf(os.Stderr, "sir: run: proxy allowlist: %s\n", strings.Join(allowedHosts, ", "))
	fmt.Fprintf(os.Stderr, "sir: run: exact destinations: %s\n", strings.Join(allowedDestinations, ", "))
	fmt.Fprintf(os.Stderr, "sir: run: proxy protocols: http-connect, socks5\n")
	if len(scrubbedEnv) > 0 {
		fmt.Fprintf(os.Stderr, "sir: run: scrubbed host-control env: %s\n", strings.Join(scrubbedEnv, ", "))
	}
	fmt.Fprintln(os.Stderr, "sir: run: write-deny list protects real hook config, canonical backups, durable sir state, and project posture files; general workspace writes remain allowed")

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	runtimeInfo := &session.RuntimeContainment{
		AgentID:                 string(opts.Agent.ID()),
		Mode:                    ContainmentModeDarwinProxy,
		ProxyURL:                proxy.URL(),
		SOCKSProxyURL:           proxy.SOCKSURL(),
		ProxyProtocols:          []string{"http-connect", "socks5"},
		AllowedHosts:            append([]string(nil), allowedHosts...),
		AllowedDestinations:     append([]string(nil), allowedDestinations...),
		AllowedHostCount:        len(allowedHosts),
		AllowedDestinationCount: len(allowedDestinations),
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
	applyProxyReceipt(runtimeInfo, proxy)
	if err := finalizeRuntimeContainment(projectRoot, runtimeInfo, exitCode); err != nil {
		return 0, err
	}
	return exitCode, nil
}
