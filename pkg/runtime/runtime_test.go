package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

type runtimeTestAgent struct{}

const (
	runtimeTestProxyShapedReason  = "proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS"
	runtimeTestScrubbedEnvReason  = "launch inherited host-control env that had to be scrubbed before containment"
	runtimeTestMaskedSocketReason = "launch inherited host-control sockets that had to be masked inside containment"
)

func (runtimeTestAgent) ID() agent.AgentID { return agent.AgentID("runtime-test") }
func (runtimeTestAgent) Name() string      { return "Runtime Test Agent" }
func (runtimeTestAgent) ParsePreToolUse([]byte) (*agent.HookPayload, error) {
	return nil, nil
}
func (runtimeTestAgent) ParsePostToolUse([]byte) (*agent.HookPayload, error) {
	return nil, nil
}
func (runtimeTestAgent) FormatPreToolUseResponse(string, string) ([]byte, error) {
	return nil, nil
}
func (runtimeTestAgent) FormatPostToolUseResponse(string, string) ([]byte, error) {
	return nil, nil
}
func (runtimeTestAgent) FormatLifecycleResponse(string, string, string, string) ([]byte, error) {
	return nil, nil
}
func (runtimeTestAgent) SupportedEvents() []string { return nil }
func (runtimeTestAgent) ConfigPath() string        { return "" }
func (runtimeTestAgent) GenerateHooksConfig(string, string) ([]byte, error) {
	return nil, nil
}
func (runtimeTestAgent) DetectInstallation() bool { return true }
func (runtimeTestAgent) MinVersion() string       { return "" }
func (runtimeTestAgent) GetSpec() *agent.AgentSpec {
	return &agent.AgentSpec{
		ID:                agent.AgentID("runtime-test"),
		Name:              "Runtime Test Agent",
		RuntimeProxyHosts: []string{"localhost"},
	}
}

func TestSelectLauncherMatchesPlatform(t *testing.T) {
	launcher := SelectLauncher()
	if launcher.Launch == nil {
		t.Fatal("SelectLauncher returned nil launch function")
	}

	switch runtime.GOOS {
	case "darwin":
		if launcher.Mode != ContainmentModeDarwinProxy {
			t.Fatalf("darwin launcher mode = %q, want %q", launcher.Mode, ContainmentModeDarwinProxy)
		}
	case "linux":
		if launcher.Mode != ContainmentModeLinuxNamespace {
			t.Fatalf("linux launcher mode = %q, want %q", launcher.Mode, ContainmentModeLinuxNamespace)
		}
	default:
		if launcher.Mode != "unsupported" {
			t.Fatalf("unsupported launcher mode = %q, want %q", launcher.Mode, "unsupported")
		}
	}
}

func TestContainmentLaunchScrubsProxyBypassEnvAndRecordsDegradation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin launcher proof is macOS-only")
	}
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}
	pythonBin, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not available")
	}

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	proofDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("HTTP_PROXY", "http://caller.proxy.invalid:8080")
	t.Setenv("HTTPS_PROXY", "https://caller.proxy.invalid:4443")
	t.Setenv("ALL_PROXY", "socks5://caller.proxy.invalid:1080")
	t.Setenv("NO_PROXY", "example.com")
	t.Setenv("http_proxy", "http://caller.proxy.invalid:8080")
	t.Setenv("https_proxy", "https://caller.proxy.invalid:4443")
	t.Setenv("all_proxy", "socks5://caller.proxy.invalid:1080")
	t.Setenv("no_proxy", "example.com")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/ssh-agent.sock")
	t.Setenv("DOCKER_HOST", "tcp://docker.invalid:2375")

	if err := os.MkdirAll(filepath.Join(homeDir, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}
	l := lease.DefaultLease()
	l.ApprovedHosts = []string{"localhost"}
	if err := l.Save(filepath.Join(session.DurableStateDir(projectRoot), "lease.json")); err != nil {
		t.Fatalf("write loopback-only runtime lease: %v", err)
	}

	agentScript := filepath.Join(binDir, "runtime-test")
	agentProgram := filepath.Join(binDir, "runtime-test.py")
	if err := os.WriteFile(agentProgram, []byte(`import json, os, socket, sys
output_path = sys.argv[1]
result = {
    key: os.environ.get(key, "")
    for key in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "SSH_AUTH_SOCK",
        "DOCKER_HOST",
    ]
}

with open(output_path, "w", encoding="utf-8") as fh:
    json.dump(result, fh)
sys.exit(0)
`), 0o755); err != nil {
		t.Fatalf("write runtime-test.py: %v", err)
	}
	if err := os.WriteFile(agentScript, []byte(fmt.Sprintf("#!/bin/sh\nexec %q %q \"$@\"\n", pythonBin, agentProgram)), 0o755); err != nil {
		t.Fatalf("write runtime-test launcher: %v", err)
	}

	outputPath := filepath.Join(proofDir, "launch-env.json")
	exitCode, err := Launch(projectRoot, Options{
		Agent:       runtimeTestAgent{},
		Passthrough: []string{outputPath},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if exitCode != 0 {
		data, _ := os.ReadFile(outputPath)
		t.Fatalf("expected Darwin launcher to succeed, exit=%d output=%s", exitCode, string(data))
	}

	var proof map[string]string
	rawProof, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read launch env proof: %v", err)
	}
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		t.Fatalf("unmarshal launch env proof: %v\n%s", err, string(rawProof))
	}
	receipt, err := session.LoadLastRuntimeContainment(projectRoot)
	if err != nil {
		t.Fatalf("load runtime receipt: %v", err)
	}
	if receipt.Mode != ContainmentModeDarwinProxy {
		t.Fatalf("runtime mode = %q, want %q", receipt.Mode, ContainmentModeDarwinProxy)
	}
	reasons := receipt.EffectiveDegradedReasons()
	if !slices.Contains(reasons, runtimeTestProxyShapedReason) {
		t.Fatalf("runtime receipt missing proxy-shaped degradation reason: %v", reasons)
	}
	if !slices.Contains(reasons, runtimeTestScrubbedEnvReason) {
		t.Fatalf("runtime receipt missing scrubbed-env degradation reason: %v", reasons)
	}
	if got, want := proof["HTTP_PROXY"], receipt.ProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("proxy env was not overridden consistently: HTTP_PROXY=%q receipt=%q", got, want)
	}
	if got, want := proof["http_proxy"], receipt.ProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("proxy env was not overridden consistently: http_proxy=%q receipt=%q", got, want)
	}
	if got, want := proof["HTTPS_PROXY"], receipt.ProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("HTTPS_PROXY = %q, want %q", got, want)
	}
	if got, want := proof["https_proxy"], receipt.ProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("https_proxy = %q, want %q", got, want)
	}
	if got, want := proof["ALL_PROXY"], receipt.SOCKSProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("ALL_PROXY = %q, want %q", got, want)
	}
	if got, want := proof["all_proxy"], receipt.SOCKSProxyURL; got == "" || want == "" || got != want {
		t.Fatalf("all_proxy = %q, want %q", got, want)
	}
	if got, want := proof["NO_PROXY"], "localhost,127.0.0.1,::1"; got != want {
		t.Fatalf("NO_PROXY = %q, want %q", got, want)
	}
	if got, want := proof["no_proxy"], "localhost,127.0.0.1,::1"; got != want {
		t.Fatalf("no_proxy = %q, want %q", got, want)
	}
	for _, key := range []string{"SSH_AUTH_SOCK", "DOCKER_HOST"} {
		if got := proof[key]; got != "" {
			t.Fatalf("expected %s to be scrubbed from child env, got %q", key, got)
		}
	}
}

func TestLaunchLinuxNamespaceProof(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux namespace proof is Linux-only")
	}
	for _, name := range []string{"unshare", "mount"} {
		requireLinuxLaunchProofBinary(t, name)
	}
	requireLinuxLaunchNamespaces(t)

	hostNetNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read host net namespace: %v", err)
	}
	hostMntNS, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read host mount namespace: %v", err)
	}

	homeDir := t.TempDir()
	projectRoot := t.TempDir()
	proofDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	binDir := t.TempDir()
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := os.MkdirAll(filepath.Join(homeDir, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	if err := lease.DefaultLease().Save(filepath.Join(session.DurableStateDir(projectRoot), "lease.json")); err != nil {
		t.Fatalf("write runtime lease: %v", err)
	}

	agentScript := filepath.Join(binDir, "runtime-test")
	if err := os.WriteFile(agentScript, []byte(`#!/bin/sh
set -eu
output_path="$1"
netns="$(readlink /proc/self/ns/net)"
mntns="$(readlink /proc/self/ns/mnt)"
printf '{"netns":"%s","mntns":"%s"}\n' "$netns" "$mntns" > "$output_path"
`), 0o755); err != nil {
		t.Fatalf("write runtime-test launcher: %v", err)
	}

	outputPath := filepath.Join(proofDir, "linux-namespace-proof.json")
	exitCode, err := Launch(projectRoot, Options{
		Agent:       runtimeTestAgent{},
		Passthrough: []string{outputPath},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	if exitCode != 0 {
		data, _ := os.ReadFile(outputPath)
		t.Fatalf("expected Linux launcher to succeed, exit=%d output=%s", exitCode, string(data))
	}

	var proof struct {
		NetNS string `json:"netns"`
		MntNS string `json:"mntns"`
	}
	rawProof, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read linux namespace proof: %v", err)
	}
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		t.Fatalf("unmarshal linux namespace proof: %v\n%s", err, string(rawProof))
	}
	if proof.NetNS == "" || proof.MntNS == "" {
		t.Fatalf("linux namespace proof missing namespace ids: %+v", proof)
	}
	if proof.NetNS == hostNetNS {
		t.Fatalf("child net namespace = %q, want distinct from host %q", proof.NetNS, hostNetNS)
	}
	if proof.MntNS == hostMntNS {
		t.Fatalf("child mount namespace = %q, want distinct from host %q", proof.MntNS, hostMntNS)
	}

	receipt, err := session.LoadLastRuntimeContainment(projectRoot)
	if err != nil {
		t.Fatalf("load runtime receipt: %v", err)
	}
	if receipt.Mode != ContainmentModeLinuxNamespace {
		t.Fatalf("runtime mode = %q, want %q", receipt.Mode, ContainmentModeLinuxNamespace)
	}
}

func requireLinuxLaunchProofBinary(t *testing.T, name string) string {
	t.Helper()
	path, err := exec.LookPath(name)
	if err == nil {
		return path
	}
	msg := fmt.Sprintf("linux namespace proof requires %s on PATH: %v", name, err)
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}

func requireLinuxLaunchNamespaces(t *testing.T) {
	t.Helper()
	cmd := exec.Command("unshare", "--user", "--map-root-user", "--net", "--mount", "--mount-proc", "/bin/sh", "-c", "readlink /proc/self/ns/net >/dev/null && readlink /proc/self/ns/mnt >/dev/null")
	output, err := cmd.CombinedOutput()
	if err == nil {
		return
	}
	msg := fmt.Sprintf("linux namespace proof requires unprivileged user+network+mount namespaces: %v", err)
	if trimmed := strings.TrimSpace(string(output)); trimmed != "" {
		msg += " (" + trimmed + ")"
	}
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		t.Fatal(msg)
	}
	t.Skip(msg)
}

func TestLinuxContainmentBootstrapScriptIncludesReadonlyGuards(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	sshSock := filepath.Join(t.TempDir(), "ssh-agent.sock")
	if err := os.WriteFile(sshSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write ssh auth sock placeholder: %v", err)
	}
	t.Setenv("SSH_AUTH_SOCK", sshSock)
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".sir", "hooks-canonical.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write hooks-canonical.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "CLAUDE.md"), []byte("# rules"), 0o644); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}
	script, err := linuxContainmentBootstrapScript(projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("linuxContainmentBootstrapScript: %v", err)
	}
	if !strings.Contains(script, "mount --make-rprivate /") {
		t.Fatalf("bootstrap script missing mount-namespace privatization:\n%s", script)
	}
	if !strings.Contains(script, "mount --rbind") {
		t.Fatalf("bootstrap script missing recursive bind for guarded directories:\n%s", script)
	}
	if !strings.Contains(script, "mount --bind") {
		t.Fatalf("bootstrap script missing bind mount for guarded files:\n%s", script)
	}
	if !strings.Contains(script, "mask_runtime_socket") || !strings.Contains(script, shellQuote(sshSock)) {
		t.Fatalf("bootstrap script missing host control socket masking for %s:\n%s", sshSock, script)
	}
	if !strings.Contains(script, shellQuote(projectRoot+"/.mcp.json")) {
		t.Fatalf("bootstrap script missing project posture guard for %s:\n%s", projectRoot+"/.mcp.json", script)
	}
}

func TestLinuxContainmentBootstrapMasksGuessedHostControlSocketsAfterEnvScrub(t *testing.T) {
	home := t.TempDir()
	xdgRuntime := t.TempDir()
	gnupgHome := filepath.Join(t.TempDir(), "gnupg")
	projectRoot := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntime)
	t.Setenv("GNUPGHOME", gnupgHome)

	socketPaths := []string{
		filepath.Join(xdgRuntime, "bus"),
		filepath.Join(xdgRuntime, "docker.sock"),
		filepath.Join(xdgRuntime, "podman", "podman.sock"),
		filepath.Join(xdgRuntime, "buildkitd.sock"),
		filepath.Join(xdgRuntime, "buildkit", "buildkitd.sock"),
		filepath.Join(xdgRuntime, "gnupg", "S.gpg-agent"),
		filepath.Join(xdgRuntime, "gnupg", "S.gpg-agent.ssh"),
		filepath.Join(home, ".gnupg", "S.gpg-agent"),
		filepath.Join(home, ".gnupg", "S.gpg-agent.browser"),
		filepath.Join(gnupgHome, "S.gpg-agent"),
		filepath.Join(gnupgHome, "S.gpg-agent.extra"),
		filepath.Join(gnupgHome, "S.gpg-agent.ssh"),
	}
	for _, path := range socketPaths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir socket dir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("socket"), 0o600); err != nil {
			t.Fatalf("write socket placeholder %s: %v", path, err)
		}
	}

	sshSock := filepath.Join(t.TempDir(), "ssh-agent.sock")
	dockerSock := filepath.Join(t.TempDir(), "docker.sock")
	dbusSock := filepath.Join(t.TempDir(), "bus")
	for _, path := range []string{sshSock, dockerSock, dbusSock} {
		if err := os.WriteFile(path, []byte("socket"), 0o600); err != nil {
			t.Fatalf("write env socket placeholder %s: %v", path, err)
		}
	}
	t.Setenv("SSH_AUTH_SOCK", sshSock)
	t.Setenv("DOCKER_HOST", "unix://"+dockerSock)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+dbusSock)

	_, scrubbed := sanitizeContainmentEnv(os.Environ())
	if !slices.Contains(scrubbed, "SSH_AUTH_SOCK") || !slices.Contains(scrubbed, "DOCKER_HOST") || !slices.Contains(scrubbed, "DBUS_SESSION_BUS_ADDRESS") {
		t.Fatalf("sanitizeContainmentEnv scrubbed = %v, want host-control env keys removed", scrubbed)
	}

	discovered := linuxHostControlSockets()
	for _, want := range []string{
		sshSock,
		dockerSock,
		dbusSock,
		filepath.Join(xdgRuntime, "bus"),
		filepath.Join(xdgRuntime, "docker.sock"),
		filepath.Join(xdgRuntime, "podman", "podman.sock"),
		filepath.Join(xdgRuntime, "buildkitd.sock"),
		filepath.Join(xdgRuntime, "buildkit", "buildkitd.sock"),
		filepath.Join(xdgRuntime, "gnupg", "S.gpg-agent"),
		filepath.Join(xdgRuntime, "gnupg", "S.gpg-agent.ssh"),
		filepath.Join(home, ".gnupg", "S.gpg-agent"),
		filepath.Join(home, ".gnupg", "S.gpg-agent.browser"),
		filepath.Join(gnupgHome, "S.gpg-agent"),
		filepath.Join(gnupgHome, "S.gpg-agent.extra"),
		filepath.Join(gnupgHome, "S.gpg-agent.ssh"),
	} {
		if !slices.Contains(discovered, want) {
			t.Fatalf("linuxHostControlSockets() = %v, want to contain %q", discovered, want)
		}
	}

	if err := os.MkdirAll(filepath.Join(home, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}

	script, err := linuxContainmentBootstrapScript(projectRoot, runtimeTestAgent{})
	if err != nil {
		t.Fatalf("linuxContainmentBootstrapScript: %v", err)
	}
	for _, want := range []string{
		"mask_runtime_socket " + shellQuote(filepath.Join(xdgRuntime, "bus")),
		"mask_runtime_socket " + shellQuote(filepath.Join(xdgRuntime, "podman", "podman.sock")),
		"mask_runtime_socket " + shellQuote(filepath.Join(xdgRuntime, "gnupg", "S.gpg-agent")),
		"mask_runtime_socket " + shellQuote(filepath.Join(home, ".gnupg", "S.gpg-agent")),
		"mask_runtime_socket " + shellQuote(filepath.Join(gnupgHome, "S.gpg-agent.ssh")),
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("bootstrap script missing %q:\n%s", want, script)
		}
	}

	receipt := &session.RuntimeContainment{
		AgentID:           string(agent.Claude),
		Mode:              ContainmentModeLinuxNamespace,
		MaskedHostSockets: append([]string(nil), discovered...),
		ScrubbedEnvVars:   append([]string(nil), scrubbed...),
	}
	reasons := receipt.EffectiveDegradedReasons()
	if !slices.Contains(reasons, runtimeTestMaskedSocketReason) {
		t.Fatalf("runtime receipt missing masked-socket degradation reason: %v", reasons)
	}
	if !slices.Contains(reasons, runtimeTestScrubbedEnvReason) {
		t.Fatalf("runtime receipt missing scrubbed-env degradation reason: %v", reasons)
	}
}

func TestLinuxContainmentAllowlistScriptIncludesHostsAndFirewallRules(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatalf("mkdir .claude: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".sir", "hooks-canonical.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write hooks-canonical.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, ".mcp.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write .mcp.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, "CLAUDE.md"), []byte("# rules"), 0o644); err != nil {
		t.Fatalf("write CLAUDE.md: %v", err)
	}

	script, err := linuxContainmentAllowlistScript(projectRoot, agent.NewClaudeAgent(), linuxAllowlistBootstrap{
		PIDFile:   filepath.Join(projectRoot, "child.pid"),
		ReadyFile: filepath.Join(projectRoot, "ready"),
		Resolved: []linuxResolvedDestination{
			{Host: "api.anthropic.com", IP: "203.0.113.10", Port: "443"},
			{Host: "api.anthropic.com", IP: "203.0.113.11", Port: "443"},
			{Host: "api.anthropic.com", IP: "2001:db8::10", Port: "443"},
		},
		HostsLines: []string{
			"203.0.113.10\tapi.anthropic.com",
			"203.0.113.11\tapi.anthropic.com",
			"2001:db8::10\tapi.anthropic.com",
		},
	})
	if err != nil {
		t.Fatalf("linuxContainmentAllowlistScript: %v", err)
	}
	for _, fragment := range []string{
		"echo $$ >",
		"while [ ! -f ",
		"hosts_override=$(mktemp",
		"iptables -P OUTPUT DROP",
		"iptables -A OUTPUT -o lo -j ACCEPT",
		"203.0.113.10",
		"203.0.113.11",
		"ip6tables -A OUTPUT -p tcp -d '2001:db8::10' --dport '443' -j ACCEPT",
		"/etc/hosts",
	} {
		if !strings.Contains(script, fragment) {
			t.Fatalf("allowlist bootstrap missing %q:\n%s", fragment, script)
		}
	}
	if strings.Contains(script, ">> /etc/hosts") {
		t.Fatalf("allowlist bootstrap must not append directly to /etc/hosts:\n%s", script)
	}
	if strings.Contains(script, "iptables -A OUTPUT -p tcp -d '2001:db8::10' --dport '443' -j ACCEPT") {
		t.Fatalf("allowlist bootstrap must not emit IPv6 destinations in the IPv4 iptables path:\n%s", script)
	}
}

func TestLinuxContainmentBootstrapScriptRejectsMissingCurrentAgentGuards(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".sir", "projects"), 0o755); err != nil {
		t.Fatalf("mkdir .sir/projects: %v", err)
	}

	_, err := linuxContainmentBootstrapScript(projectRoot, agent.NewClaudeAgent())
	if err == nil {
		t.Fatal("expected missing current-agent guard paths to fail closed")
	}
	if !strings.Contains(err.Error(), filepath.Join(home, ".claude")) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLinuxHostControlSocketsCollectsExistingUnixEndpoints(t *testing.T) {
	sshSock := filepath.Join(t.TempDir(), "ssh-agent.sock")
	if err := os.WriteFile(sshSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write ssh auth sock placeholder: %v", err)
	}
	dockerSock := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.WriteFile(dockerSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write docker sock placeholder: %v", err)
	}
	podmanDir := t.TempDir()
	podmanSock := filepath.Join(podmanDir, "podman", "podman.sock")
	if err := os.MkdirAll(filepath.Dir(podmanSock), 0o755); err != nil {
		t.Fatalf("mkdir podman dir: %v", err)
	}
	if err := os.WriteFile(podmanSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write podman sock placeholder: %v", err)
	}
	dbusSock := filepath.Join(t.TempDir(), "bus")
	if err := os.WriteFile(dbusSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write dbus sock placeholder: %v", err)
	}
	homeDir := t.TempDir()
	gpgDir := filepath.Join(homeDir, ".gnupg")
	if err := os.MkdirAll(gpgDir, 0o755); err != nil {
		t.Fatalf("mkdir gpg dir: %v", err)
	}
	gpgSock := filepath.Join(gpgDir, "S.gpg-agent")
	if err := os.WriteFile(gpgSock, []byte("socket"), 0o600); err != nil {
		t.Fatalf("write gpg sock placeholder: %v", err)
	}

	t.Setenv("SSH_AUTH_SOCK", sshSock)
	t.Setenv("DOCKER_HOST", "unix://"+dockerSock)
	t.Setenv("XDG_RUNTIME_DIR", podmanDir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+dbusSock)
	t.Setenv("HOME", homeDir)

	got := linuxHostControlSockets()
	want := []string{dbusSock, dockerSock, gpgSock, podmanSock, sshSock}
	for _, expected := range want {
		if !slices.Contains(got, expected) {
			t.Fatalf("linuxHostControlSockets() = %v, want to contain %q", got, expected)
		}
	}
}

func TestSanitizeContainmentEnvRemovesHostControlKeys(t *testing.T) {
	base := []string{
		"SSH_AUTH_SOCK=/tmp/ssh.sock",
		"DOCKER_HOST=unix:///tmp/docker.sock",
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/tmp/dbus.sock",
		"PATH=/usr/bin",
	}
	sanitized, scrubbed := sanitizeContainmentEnv(base)
	if strings.Join(scrubbed, ",") != "SSH_AUTH_SOCK,DOCKER_HOST,DBUS_SESSION_BUS_ADDRESS" {
		t.Fatalf("scrubbed env = %v", scrubbed)
	}
	if strings.Join(sanitized, ",") != "PATH=/usr/bin" {
		t.Fatalf("sanitized env = %v", sanitized)
	}
}

func TestStartLocalProxyPinsResolvedIPs(t *testing.T) {
	resolvedIPs := []string{"203.0.113.10", "203.0.113.11"}
	proxy, err := startLocalProxyWithResolver([]string{"api.anthropic.com"}, func(_ context.Context, host string) ([]string, error) {
		if host != "api.anthropic.com" {
			t.Fatalf("resolver host = %q, want api.anthropic.com", host)
		}
		return append([]string(nil), resolvedIPs...), nil
	})
	if err != nil {
		t.Fatalf("startLocalProxyWithResolver: %v", err)
	}
	defer proxy.Close()

	// Simulate resolver drift after launch; the proxy must stay pinned to the
	// launch-time answers it already captured.
	resolvedIPs = []string{"198.51.100.22"}

	if !proxy.isAllowed("api.anthropic.com", "443") {
		t.Fatal("expected hostname to stay allowlisted")
	}
	if proxy.isAllowed("api.anthropic.com", "8443") {
		t.Fatal("expected non-default port to stay blocked without an explicit destination rule")
	}
	if proxy.isAllowed("203.0.113.10", "443") {
		t.Fatal("expected direct IP request to stay blocked without an explicit IP allowlist")
	}
	if proxy.isAllowed("198.51.100.22", "443") {
		t.Fatal("unexpected unrelated IP allowlist match")
	}
	if got := proxy.pinnedHosts["api.anthropic.com"]; !slices.Equal(got, []string{"203.0.113.10", "203.0.113.11"}) {
		t.Fatalf("pinned hosts = %v, want launch-time resolver answers", got)
	}
	got := proxy.allowedDialTargets("api.anthropic.com", "443")
	want := []string{"203.0.113.10:443", "203.0.113.11:443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("allowedDialTargets = %v, want %v", got, want)
	}
}

func TestStartLocalProxyTracksHTTPEgressDecisions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy, err := StartLocalProxy([]string{NormalizeProxyHost(upstream.URL)})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read allowed proxy response: %v", err)
	}

	blockedResp, err := client.Get("http://127.0.0.2/")
	if err != nil {
		t.Fatalf("GET blocked host via proxy: %v", err)
	}
	defer blockedResp.Body.Close()
	if blockedResp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status = %d, want %d", blockedResp.StatusCode, http.StatusForbidden)
	}

	stats := proxy.snapshotStats()
	if stats.allowedEgressCount != 1 || stats.blockedEgressCount != 1 {
		t.Fatalf("unexpected proxy stats: %+v", stats)
	}
	if stats.lastBlockedDest != "127.0.0.2:80" {
		t.Fatalf("lastBlockedDest = %q, want %q", stats.lastBlockedDest, "127.0.0.2:80")
	}
}

func TestStartLocalProxyBlocksRedirectBounceToUnapprovedHost(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.2/escape", http.StatusFound)
	}))
	defer origin.Close()

	proxy, err := StartLocalProxy([]string{NormalizeProxyHost(origin.URL)})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
	}

	resp, err := client.Get(origin.URL)
	if err != nil {
		t.Fatalf("GET redirect bounce via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read redirect bounce response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("redirect bounce status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
	if !strings.Contains(string(body), "sir run proxy blocked destination \"127.0.0.2:80\"") {
		t.Fatalf("redirect bounce response body = %q, want blocked second-hop destination", string(body))
	}

	stats := proxy.snapshotStats()
	if stats.allowedEgressCount != 1 || stats.blockedEgressCount != 1 {
		t.Fatalf("unexpected proxy stats: %+v", stats)
	}
	if stats.lastBlockedDest != "127.0.0.2:80" {
		t.Fatalf("lastBlockedDest = %q, want %q", stats.lastBlockedDest, "127.0.0.2:80")
	}
}

func TestSignalLinuxContainmentReady_CleansUpOnWriteError(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper process: %v", err)
	}

	cleanupCalls := 0
	err := signalLinuxContainmentReady(
		cmd,
		filepath.Join(t.TempDir(), "missing", "ready"),
		func() { cleanupCalls++ },
	)
	if err == nil {
		t.Fatal("expected ready-file error")
	}
	if !strings.Contains(err.Error(), "signal linux containment readiness") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanupCalls = %d, want 1", cleanupCalls)
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err == nil {
		t.Fatal("expected helper process to be gone after readiness failure")
	}
}

func TestStartLocalProxyTracksSOCKSEgressDecisions(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	proxy, err := StartLocalProxy([]string{NormalizeProxyHost(upstream.URL)})
	if err != nil {
		t.Fatalf("StartLocalProxy: %v", err)
	}
	defer proxy.Close()

	socksURL, _ := url.Parse(proxy.SOCKSURL())
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(socksURL)},
	}

	resp, err := client.Get(upstream.URL)
	if err != nil {
		t.Fatalf("GET via socks proxy: %v", err)
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read socks proxy response: %v", err)
	}

	if _, err := client.Get("http://127.0.0.2/"); err == nil {
		t.Fatal("expected blocked socks proxy request to fail")
	}

	stats := proxy.snapshotStats()
	if stats.allowedEgressCount != 1 || stats.blockedEgressCount != 1 {
		t.Fatalf("unexpected proxy stats: %+v", stats)
	}
	if stats.lastBlockedDest != "127.0.0.2:80" {
		t.Fatalf("lastBlockedDest = %q, want %q", stats.lastBlockedDest, "127.0.0.2:80")
	}
}

func TestResolveRuntimeDestinationsPinsHostsToExactDestinations(t *testing.T) {
	allowlist := buildRuntimeAllowlist([]string{"api.anthropic.com", "api.anthropic.com:8443", "127.0.0.1:3000"})
	resolved, err := resolveRuntimeDestinations(allowlist, func(_ context.Context, host string) ([]string, error) {
		if host != "api.anthropic.com" {
			t.Fatalf("resolver host = %q, want api.anthropic.com", host)
		}
		return []string{"203.0.113.10", "203.0.113.11"}, nil
	})
	if err != nil {
		t.Fatalf("resolveRuntimeDestinations: %v", err)
	}
	got := make([]string, 0, len(resolved))
	for _, dest := range resolved {
		got = append(got, fmt.Sprintf("%s=%s:%s", dest.Host, dest.IP, dest.Port))
	}
	want := []string{
		"127.0.0.1=127.0.0.1:3000",
		"api.anthropic.com=203.0.113.10:22",
		"api.anthropic.com=203.0.113.10:80",
		"api.anthropic.com=203.0.113.10:443",
		"api.anthropic.com=203.0.113.10:8443",
		"api.anthropic.com=203.0.113.11:22",
		"api.anthropic.com=203.0.113.11:80",
		"api.anthropic.com=203.0.113.11:443",
		"api.anthropic.com=203.0.113.11:8443",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("resolved destinations = %v, want %v", got, want)
	}
}

func TestLinuxHostsLinesSkipsLoopbackAndDedupes(t *testing.T) {
	lines := linuxHostsLines([]linuxResolvedDestination{
		{Host: "api.anthropic.com", IP: "203.0.113.10", Port: "443"},
		{Host: "api.anthropic.com", IP: "203.0.113.10", Port: "80"},
		{Host: "localhost", IP: "127.0.0.1", Port: "3000"},
	})
	want := []string{"203.0.113.10\tapi.anthropic.com"}
	if strings.Join(lines, ",") != strings.Join(want, ",") {
		t.Fatalf("linuxHostsLines = %v, want %v", lines, want)
	}
}

func TestAllowedDialTargetsPreferPinnedIPs(t *testing.T) {
	proxy := &LocalProxy{
		allowlist: runtimeAllowlist{
			portsByHost: map[string]map[string]struct{}{
				"api.anthropic.com": {"443": {}},
			},
		},
		pinnedHosts: map[string][]string{
			"api.anthropic.com": {"203.0.113.10", "203.0.113.11"},
		},
	}
	got := proxy.allowedDialTargets("api.anthropic.com", "443")
	want := []string{"203.0.113.10:443", "203.0.113.11:443"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("allowedDialTargets = %v, want %v", got, want)
	}
}

func TestDialAllowedTargetUsesPinnedIPs(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- struct{}{}
		_ = conn.Close()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	proxy := &LocalProxy{
		allowlist: runtimeAllowlist{
			portsByHost: map[string]map[string]struct{}{
				"api.anthropic.com": {fmt.Sprintf("%d", port): {}},
			},
		},
		pinnedHosts: map[string][]string{
			"api.anthropic.com": {"127.0.0.1"},
		},
	}
	conn, err := proxy.dialAllowedTarget(context.Background(), "tcp", "api.anthropic.com", fmt.Sprintf("%d", port))
	if err != nil {
		t.Fatalf("dialAllowedTarget: %v", err)
	}
	_ = conn.Close()

	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("expected pinned IP dial to reach listener")
	}
}

func TestDialAllowedTargetUsesBoundedPerTargetTimeout(t *testing.T) {
	pipeClient, pipeServer := net.Pipe()
	defer pipeServer.Close()

	var deadlines []time.Duration
	proxy := &LocalProxy{
		allowlist: runtimeAllowlist{
			portsByHost: map[string]map[string]struct{}{
				"api.anthropic.com": {"443": {}},
			},
		},
		pinnedHosts: map[string][]string{
			"api.anthropic.com": {"203.0.113.10", "203.0.113.11"},
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("expected per-target deadline on proxy dial")
			}
			deadlines = append(deadlines, time.Until(deadline))
			if len(deadlines) == 1 {
				return nil, errors.New("first pinned target unavailable")
			}
			return pipeClient, nil
		},
	}

	conn, err := proxy.dialAllowedTarget(context.Background(), "tcp", "api.anthropic.com", "443")
	if err != nil {
		t.Fatalf("dialAllowedTarget: %v", err)
	}
	_ = conn.Close()

	if len(deadlines) != 2 {
		t.Fatalf("dial attempts = %d, want 2", len(deadlines))
	}
	for _, got := range deadlines {
		if got > proxyDialAttemptTimeout+250*time.Millisecond {
			t.Fatalf("per-target timeout = %v, want <= %v", got, proxyDialAttemptTimeout+250*time.Millisecond)
		}
	}
}

func TestBuildRuntimeAllowlistExpandsExternalHostsToExactDefaultPorts(t *testing.T) {
	allowlist := buildRuntimeAllowlist([]string{"api.anthropic.com"})
	if !allowlist.Allows("api.anthropic.com", "443") {
		t.Fatal("expected 443 to be allowed for host-only external entry")
	}
	if !allowlist.Allows("api.anthropic.com", "80") {
		t.Fatal("expected 80 to be allowed for host-only external entry")
	}
	if !allowlist.Allows("api.anthropic.com", "22") {
		t.Fatal("expected 22 to be allowed for host-only external entry")
	}
	if allowlist.Allows("api.anthropic.com", "8443") {
		t.Fatal("unexpected non-default external port allowance")
	}
}

func TestBuildRuntimeAllowlistKeepsLoopbackWildcardPorts(t *testing.T) {
	allowlist := buildRuntimeAllowlist([]string{"localhost", "127.0.0.1"})
	if !allowlist.Allows("localhost", "3000") {
		t.Fatal("expected loopback host-only entry to allow arbitrary local ports")
	}
	if !allowlist.Allows("127.0.0.1", "3000") {
		t.Fatal("expected loopback IP host-only entry to allow arbitrary local ports")
	}
}

func TestBuildRuntimeAllowlistHonorsExplicitPortDestinations(t *testing.T) {
	allowlist := buildRuntimeAllowlist([]string{"api.anthropic.com:8443"})
	if !allowlist.Allows("api.anthropic.com", "8443") {
		t.Fatal("expected explicit destination port to be allowed")
	}
	if allowlist.Allows("api.anthropic.com", "443") {
		t.Fatal("unexpected fallback to default ports for explicit destination")
	}
}

func TestStartLocalProxyUsesResolverTimeout(t *testing.T) {
	proxy, err := startLocalProxyWithResolver([]string{"api.anthropic.com"}, func(ctx context.Context, host string) ([]string, error) {
		if host != "api.anthropic.com" {
			t.Fatalf("resolver host = %q, want api.anthropic.com", host)
		}
		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatal("expected resolver timeout deadline")
		}
		if remaining := time.Until(deadline); remaining > proxyResolverTimeout+250*time.Millisecond {
			t.Fatalf("resolver timeout = %v, want <= %v", remaining, proxyResolverTimeout+250*time.Millisecond)
		}
		return []string{"203.0.113.10"}, nil
	})
	if err != nil {
		t.Fatalf("startLocalProxyWithResolver: %v", err)
	}
	defer proxy.Close()
}

func TestSOCKSURLUsesHostnamePreservingScheme(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	proxy := &LocalProxy{socksListener: listener}
	if got := proxy.SOCKSURL(); !strings.HasPrefix(got, "socks5h://") {
		t.Fatalf("SOCKSURL() = %q, want socks5h:// prefix", got)
	}
}

func TestResolveBinaryRejectsNilAgent(t *testing.T) {
	if _, err := ResolveBinary(nil); err == nil {
		t.Fatal("expected ResolveBinary(nil) to fail")
	}
}

func TestLaunchRejectsNilAgent(t *testing.T) {
	if _, err := Launch(t.TempDir(), Options{}); err == nil {
		t.Fatal("expected Launch with nil agent to fail")
	}
}
