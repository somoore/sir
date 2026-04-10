package main

import (
	"os"

	"github.com/somoore/sir/pkg/agent"
	runtimepkg "github.com/somoore/sir/pkg/runtime"
)

type runOptions struct {
	agent        agent.Agent
	allowedHosts []string
	passthrough  []string
}

type runLauncher struct {
	mode   string
	launch func(projectRoot, bin string, opts runOptions) (int, error)
}

const (
	runContainmentModeDarwinProxy    = runtimepkg.ContainmentModeDarwinProxy
	runContainmentModeLinuxNamespace = runtimepkg.ContainmentModeLinuxNamespace
)

func toRuntimeOptions(opts runOptions) runtimepkg.Options {
	return runtimepkg.Options{
		Agent:        opts.agent,
		AllowedHosts: append([]string(nil), opts.allowedHosts...),
		Passthrough:  append([]string(nil), opts.passthrough...),
	}
}

func fromRuntimeOptions(opts runtimepkg.Options) runOptions {
	return runOptions{
		agent:        opts.Agent,
		allowedHosts: append([]string(nil), opts.AllowedHosts...),
		passthrough:  append([]string(nil), opts.Passthrough...),
	}
}

func parseRunOptions(args []string) (runOptions, error) {
	opts, err := runtimepkg.ParseOptions(args)
	if err != nil {
		return runOptions{}, err
	}
	return fromRuntimeOptions(opts), nil
}

func cmdRun(projectRoot string, args []string) {
	opts, err := parseRunOptions(args)
	if err != nil {
		fatal("%v", err)
	}
	exitCode, err := runtimepkg.Launch(projectRoot, toRuntimeOptions(opts))
	if err != nil {
		fatal("sir run: %v", err)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}

func resolveRunBinary(ag agent.Agent) (string, error) {
	return runtimepkg.ResolveBinary(ag)
}

func buildRunDarwinProfile(projectRoot string, opts runOptions) (string, error) {
	return runtimepkg.BuildDarwinProfile(projectRoot, toRuntimeOptions(opts))
}

func runProxyEnv(httpProxyURL, socksProxyURL string) map[string]string {
	return runtimepkg.RunProxyEnv(httpProxyURL, socksProxyURL)
}

func classifyWrappedAgentExit(err error) (int, error) {
	return runtimepkg.ClassifyWrappedAgentExit(err)
}

func seedRunShadowState(projectRoot, stateHome string) error {
	return runtimepkg.SeedShadowState(projectRoot, stateHome)
}

func withEnvOverride(base []string, key, value string) []string {
	return runtimepkg.WithEnvOverride(base, key, value)
}

func selectRunLauncher() runLauncher {
	launcher := runtimepkg.SelectLauncher()
	return runLauncher{
		mode: launcher.Mode,
		launch: func(projectRoot, bin string, opts runOptions) (int, error) {
			return launcher.Launch(projectRoot, bin, toRuntimeOptions(opts))
		},
	}
}

type runLocalProxy = runtimepkg.LocalProxy

func startRunLocalProxy(allowedHosts []string) (*runLocalProxy, error) {
	return runtimepkg.StartLocalProxy(allowedHosts)
}

func runProxyAllowedHosts(projectRoot string, opts runOptions) ([]string, error) {
	return runtimepkg.RunProxyAllowedHosts(projectRoot, toRuntimeOptions(opts))
}

func runProxyAllowedDestinations(projectRoot string, opts runOptions) ([]string, error) {
	return runtimepkg.RunProxyAllowedDestinations(projectRoot, toRuntimeOptions(opts))
}

func normalizeRunProxyHost(raw string) string {
	return runtimepkg.NormalizeProxyHost(raw)
}
