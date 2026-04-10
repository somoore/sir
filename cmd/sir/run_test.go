package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/session"
)

func TestParseRunOptions(t *testing.T) {
	opts, err := parseRunOptions([]string{"claude", "--allow-host", "api.anthropic.com", "--", "--resume"})
	if err != nil {
		t.Fatalf("parseRunOptions: %v", err)
	}
	if opts.agent == nil || opts.agent.ID() != "claude" {
		t.Fatalf("expected claude agent, got %#v", opts.agent)
	}
	if len(opts.allowedHosts) != 1 || opts.allowedHosts[0] != "api.anthropic.com" {
		t.Fatalf("expected allow-host to parse, got %v", opts.allowedHosts)
	}
	if len(opts.passthrough) != 1 || opts.passthrough[0] != "--resume" {
		t.Fatalf("expected passthrough args after --, got %v", opts.passthrough)
	}
}

func TestParseRunOptions_UnknownAgent(t *testing.T) {
	if _, err := parseRunOptions([]string{"unknown"}); err == nil {
		t.Fatal("expected unknown agent error")
	}
}

func TestParseRunOptions_MissingAllowHostValue(t *testing.T) {
	if _, err := parseRunOptions([]string{"claude", "--allow-host"}); err == nil {
		t.Fatal("expected missing allow-host value error")
	}
}

func TestResolveRunBinaryFallsBackToAgentID(t *testing.T) {
	binDir := t.TempDir()
	claudePath := filepath.Join(binDir, "claude")
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake claude binary: %v", err)
	}
	t.Setenv("PATH", binDir)

	got, err := resolveRunBinary(agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("resolveRunBinary(claude): %v", err)
	}
	if got != claudePath {
		t.Fatalf("resolveRunBinary(claude) = %q, want %q", got, claudePath)
	}
}

func TestBuildRunDarwinProfileProtectsPostureFiles(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)

	profile, err := buildRunDarwinProfile(projectRoot, runOptions{agent: agent.NewClaudeAgent()})
	if err != nil {
		t.Fatalf("buildRunDarwinProfile: %v", err)
	}

	wantFragments := []string{
		"(deny network-outbound)",
		`(allow network-outbound (remote ip "localhost:*"))`,
		`(deny file-write* (subpath "` + filepath.Join(homeDir, ".claude") + `"))`,
		`(deny file-write* (subpath "` + filepath.Join(homeDir, ".sir", "projects") + `"))`,
		`(deny file-write* (literal "` + filepath.Join(homeDir, ".claude", "settings.json") + `"))`,
		`(deny file-write* (literal "` + filepath.Join(homeDir, ".sir", "hooks-canonical.json") + `"))`,
		`(deny file-write* (literal "` + filepath.Join(homeDir, ".codex", "config.toml") + `"))`,
		`(deny file-write* (literal "` + filepath.Join(projectRoot, ".mcp.json") + `"))`,
		`(deny file-write* (literal "` + filepath.Join(projectRoot, "CLAUDE.md") + `"))`,
	}
	for _, fragment := range wantFragments {
		if !strings.Contains(profile, fragment) {
			t.Fatalf("sandbox profile missing %q\nprofile:\n%s", fragment, profile)
		}
	}
	if strings.Contains(profile, `(deny file-write* (subpath "`+filepath.Join(homeDir, ".sir")+`"))`) {
		t.Fatalf("sandbox profile should not blanket-deny ~/.sir root:\n%s", profile)
	}
}

func TestBuildRunDarwinProfileAllowHostKeepsLocalhostSandbox(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)

	profile, err := buildRunDarwinProfile(projectRoot, runOptions{
		agent:        agent.NewClaudeAgent(),
		allowedHosts: []string{"api.anthropic.com"},
	})
	if err != nil {
		t.Fatalf("buildRunDarwinProfile: %v", err)
	}
	for _, fragment := range []string{
		"(deny network-outbound)",
		`(allow network-outbound (remote ip "localhost:*"))`,
		`(deny file-write* (literal "` + filepath.Join(homeDir, ".claude", "settings.json") + `"))`,
	} {
		if !strings.Contains(profile, fragment) {
			t.Fatalf("allow-host profile missing %q:\n%s", fragment, profile)
		}
	}
}

func TestBuildRunDarwinProfileUsesDurableStateDir(t *testing.T) {
	homeDir := t.TempDir()
	overrideHome := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv(session.StateHomeEnvVar, overrideHome)

	profile, err := buildRunDarwinProfile(projectRoot, runOptions{agent: agent.NewClaudeAgent()})
	if err != nil {
		t.Fatalf("buildRunDarwinProfile: %v", err)
	}
	if !strings.Contains(profile, filepath.Join(homeDir, ".sir", "projects")) {
		t.Fatalf("profile should protect the durable HOME state root:\n%s", profile)
	}
	if strings.Contains(profile, filepath.Join(overrideHome, ".sir", "projects")) {
		t.Fatalf("profile should not key durable protection off %s override:\n%s", session.StateHomeEnvVar, profile)
	}
}

func TestBuildRunDarwinProfileProtectsOtherProjectStateTrees(t *testing.T) {
	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)

	profile, err := buildRunDarwinProfile(projectRoot, runOptions{agent: agent.NewClaudeAgent()})
	if err != nil {
		t.Fatalf("buildRunDarwinProfile: %v", err)
	}

	otherProjectState := filepath.Join(homeDir, ".sir", "projects", "some-other-project-hash", "lease.json")
	if !strings.Contains(profile, `(deny file-write* (subpath "`+filepath.Join(homeDir, ".sir", "projects")+`"))`) {
		t.Fatalf("profile must deny the entire durable state root:\n%s", profile)
	}
	if strings.Contains(profile, `(deny file-write* (literal "`+otherProjectState+`"))`) {
		t.Fatalf("profile should rely on the durable state root deny, not per-project literals:\n%s", profile)
	}
}

func TestWithEnvOverrideReplacesExistingValue(t *testing.T) {
	got := withEnvOverride([]string{"A=1", "SIR_STATE_HOME=/tmp/old"}, "SIR_STATE_HOME", "/tmp/new")
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "SIR_STATE_HOME=/tmp/old") {
		t.Fatalf("old env value still present: %v", got)
	}
	if !strings.Contains(joined, "SIR_STATE_HOME=/tmp/new") {
		t.Fatalf("new env value missing: %v", got)
	}
}

func TestRunProxyEnvLimitsNoProxyToLoopback(t *testing.T) {
	env := runProxyEnv("http://127.0.0.1:7777", "socks5://127.0.0.1:8888")
	for _, key := range []string{"NO_PROXY", "no_proxy"} {
		if got := env[key]; got != "localhost,127.0.0.1,::1" {
			t.Fatalf("%s = %q, want loopback-only list", key, got)
		}
		if strings.Contains(env[key], "host.docker.internal") {
			t.Fatalf("%s should not exempt host.docker.internal: %q", key, env[key])
		}
	}
	for _, key := range []string{"ALL_PROXY", "all_proxy"} {
		if got := env[key]; got != "socks5://127.0.0.1:8888" {
			t.Fatalf("%s = %q, want socks5 proxy", key, got)
		}
	}
}

func TestSelectRunLauncher(t *testing.T) {
	launcher := selectRunLauncher()
	if launcher.launch == nil {
		t.Fatal("selectRunLauncher returned nil launch function")
	}
	if runtime.GOOS == "darwin" && launcher.mode != runContainmentModeDarwinProxy {
		t.Fatalf("darwin launcher mode = %q, want %q", launcher.mode, runContainmentModeDarwinProxy)
	}
	if runtime.GOOS == "linux" && launcher.mode != runContainmentModeLinuxNamespace {
		t.Fatalf("linux launcher mode = %q, want %q", launcher.mode, runContainmentModeLinuxNamespace)
	}
}

func TestClassifyWrappedAgentExitReturnsExitCode(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 7")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit")
	}
	code, classifyErr := classifyWrappedAgentExit(err)
	if classifyErr != nil {
		t.Fatalf("classifyWrappedAgentExit returned error: %v", classifyErr)
	}
	if code != 7 {
		t.Fatalf("classifyWrappedAgentExit returned code %d, want 7", code)
	}
}

func TestSandboxExecAcceptsGeneratedProfile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("sandbox-exec runtime validation is macOS-only")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	t.Setenv("HOME", homeDir)

	profile, err := buildRunDarwinProfile(projectRoot, runOptions{agent: agent.NewClaudeAgent()})
	if err != nil {
		t.Fatalf("buildRunDarwinProfile: %v", err)
	}

	cmd := exec.Command("sandbox-exec", "-p", profile, "/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("sandbox-exec rejected generated profile: %v", err)
	}
}
