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

type linuxLaunchPlan struct {
	requiredBinaries []string
	unshareArgs      []string
	bootstrap        linuxAllowlistBootstrap
	announce         func(maskedSockets, scrubbedEnv []string)
	buildRuntimeInfo func(projectRoot string, opts Options, stateHome string, cmd *exec.Cmd, scrubbedEnv []string) (*session.RuntimeContainment, func(), error)
}

func runAgentLinux(projectRoot, bin string, opts Options) (int, error) {
	if len(opts.AllowedHosts) > 0 {
		return runAgentLinuxAllowlist(projectRoot, bin, opts)
	}
	return runAgentLinuxOffline(projectRoot, bin, opts)
}

func runAgentLinuxOffline(projectRoot, bin string, opts Options) (int, error) {
	maskedSockets := linuxHostControlSockets()
	return runAgentLinuxLifecycle(projectRoot, bin, opts, linuxLaunchPlan{
		requiredBinaries: []string{"unshare", "mount"},
		unshareArgs: []string{
			"--user",
			"--map-root-user",
			"--net",
			"--mount",
			"--mount-proc",
		},
		bootstrap: linuxAllowlistBootstrap{
			MaskedSockets: maskedSockets,
		},
		announce: func(maskedSockets, scrubbedEnv []string) {
			fmt.Fprintln(os.Stderr, "sir: run: experimental containment (Linux network namespace with outbound egress denied)")
			fmt.Fprintln(os.Stderr, "sir: run: no external network is available inside this containment mode")
			if len(maskedSockets) > 0 {
				fmt.Fprintf(os.Stderr, "sir: run: masked host control sockets: %s\n", strings.Join(maskedSockets, ", "))
			}
			if len(scrubbedEnv) > 0 {
				fmt.Fprintf(os.Stderr, "sir: run: scrubbed host-control env: %s\n", strings.Join(scrubbedEnv, ", "))
			}
			fmt.Fprintln(os.Stderr, "sir: run: write-deny list protects the current agent's real hook config, canonical backups, durable sir state, and shared posture files; general workspace writes remain allowed once those guarded paths exist")
		},
		buildRuntimeInfo: func(projectRoot string, opts Options, stateHome string, cmd *exec.Cmd, scrubbedEnv []string) (*session.RuntimeContainment, func(), error) {
			return &session.RuntimeContainment{
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
			}, nil, nil
		},
	})
}

func runAgentLinuxAllowlist(projectRoot, bin string, opts Options) (int, error) {
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

	maskedSockets := linuxHostControlSockets()
	syncDir, err := os.MkdirTemp("", "sir-run-linux-sync-*")
	if err != nil {
		return 0, fmt.Errorf("create linux containment sync dir: %w", err)
	}
	defer os.RemoveAll(syncDir)
	pidFile := syncDir + "/child.pid"
	readyFile := syncDir + "/ready"

	return runAgentLinuxLifecycle(projectRoot, bin, opts, linuxLaunchPlan{
		requiredBinaries: []string{"unshare", "mount", "slirp4netns", "iptables"},
		unshareArgs: []string{
			"--fork",
			"--user",
			"--map-root-user",
			"--net",
			"--mount",
			"--mount-proc",
		},
		bootstrap: linuxAllowlistBootstrap{
			PIDFile:       pidFile,
			ReadyFile:     readyFile,
			Resolved:      resolved,
			HostsLines:    linuxHostsLines(resolved),
			MaskedSockets: maskedSockets,
		},
		announce: func(maskedSockets, scrubbedEnv []string) {
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
		},
		buildRuntimeInfo: func(projectRoot string, opts Options, stateHome string, cmd *exec.Cmd, scrubbedEnv []string) (runtimeInfo *session.RuntimeContainment, cleanup func(), err error) {
			childPID, err := waitForLinuxNamespacePID(pidFile, 2*time.Second)
			if err != nil {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
				return nil, nil, fmt.Errorf("discover linux containment child pid: %w", err)
			}

			slirp := exec.Command("slirp4netns", "--configure", "--disable-host-loopback", strconv.Itoa(childPID), "tap0")
			slirp.Stdout = os.Stderr
			slirp.Stderr = os.Stderr
			if err := slirp.Start(); err != nil {
				_ = cmd.Process.Kill()
				_, _ = cmd.Process.Wait()
				return nil, nil, fmt.Errorf("start linux user-mode network: %w", err)
			}

			cleanup = func() {
				if slirp.Process != nil {
					_ = slirp.Process.Kill()
					_, _ = slirp.Process.Wait()
				}
			}
			if err := signalLinuxContainmentReady(cmd, readyFile, cleanup); err != nil {
				return nil, nil, err
			}

			allowedHosts := allowlist.Hosts()
			allowedDestinations := allowlist.Destinations()
			runtimeInfo = &session.RuntimeContainment{
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
			return runtimeInfo, cleanup, nil
		},
	})
}

func runAgentLinuxLifecycle(projectRoot, bin string, opts Options, plan linuxLaunchPlan) (int, error) {
	for _, name := range plan.requiredBinaries {
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

	script, err := linuxContainmentAllowlistScript(projectRoot, opts.Agent, plan.bootstrap)
	if err != nil {
		return 0, fmt.Errorf("build linux containment bootstrap: %w", err)
	}
	unshareArgs := append([]string{}, plan.unshareArgs...)
	unshareArgs = append(unshareArgs, "/bin/sh", "-c", script, "sh", bin)
	unshareArgs = append(unshareArgs, opts.Passthrough...)

	cmd := exec.Command("unshare", unshareArgs...)
	baseEnv, scrubbedEnv := sanitizeContainmentEnv(os.Environ())
	cmd.Env = WithEnvOverride(baseEnv, session.StateHomeEnvVar, stateHome)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if plan.announce != nil {
		plan.announce(plan.bootstrap.MaskedSockets, scrubbedEnv)
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}

	runtimeInfo, cleanup, err := plan.buildRuntimeInfo(projectRoot, opts, stateHome, cmd, scrubbedEnv)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 0, err
	}
	if cleanup != nil {
		defer cleanup()
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

func signalLinuxContainmentReady(cmd *exec.Cmd, readyFile string, cleanup func()) error {
	if err := os.WriteFile(readyFile, []byte("ready\n"), 0o600); err != nil {
		if cleanup != nil {
			cleanup()
		}
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return fmt.Errorf("signal linux containment readiness: %w", err)
	}
	return nil
}
