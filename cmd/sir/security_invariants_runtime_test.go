package main

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	runtimepkg "github.com/somoore/sir/pkg/runtime"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantRuntimeContainmentFailclosed(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	if goruntime.GOOS != "linux" {
		t.Skip("linux-only containment fail-closed invariant")
	}

	env := newTestEnv(t)
	binDir := t.TempDir()
	claudeBin := filepath.Join(binDir, "claude")
	if err := os.WriteFile(claudeBin, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake claude binary: %v", err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	_, err := runtimepkg.Launch(env.projectRoot, runtimepkg.Options{Agent: agent.NewClaudeAgent()})
	if err == nil {
		t.Fatal("expected linux containment to fail closed without current-agent guard paths")
	}
	if !strings.Contains(err.Error(), fixture.Expected["error_contains"]) {
		t.Fatalf("containment error = %q, want substring %q", err.Error(), fixture.Expected["error_contains"])
	}
}

func runInvariantCodexBashOnlyBoundary(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	manifest := agent.SupportManifestForAgent(agent.NewCodexAgent())
	if got, want := string(manifest.SupportTier), fixture.Expected["support_tier"]; got != want {
		t.Fatalf("Codex support tier = %q, want %q", got, want)
	}
	if got, want := string(manifest.ToolCoverage), fixture.Expected["tool_coverage"]; got != want {
		t.Fatalf("Codex tool coverage = %q, want %q", got, want)
	}
	for _, surface := range manifest.Surfaces {
		if surface.Key == agent.SurfaceMCPToolHooks && surface.Supported {
			t.Fatal("Codex must not claim MCP tool hook support")
		}
	}
}

func runInvariantExactDestinationPolicy(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	env.writeDefaultLease()

	baseline, err := runProxyAllowedDestinations(env.projectRoot, runOptions{
		agent: agent.NewClaudeAgent(),
	})
	if err != nil {
		t.Fatalf("runProxyAllowedDestinations baseline: %v", err)
	}
	got, err := runProxyAllowedDestinations(env.projectRoot, runOptions{
		agent:        agent.NewClaudeAgent(),
		allowedHosts: append([]string(nil), fixture.AllowedHosts...),
	})
	if err != nil {
		t.Fatalf("runProxyAllowedDestinations: %v", err)
	}

	baselineSet := make(map[string]struct{}, len(baseline))
	for _, destination := range baseline {
		baselineSet[destination] = struct{}{}
	}
	added := make([]string, 0)
	for _, destination := range got {
		if _, ok := baselineSet[destination]; ok {
			continue
		}
		added = append(added, destination)
	}
	sort.Strings(added)
	if want := fixture.Expected["exact_destinations"]; strings.Join(added, ",") != want {
		t.Fatalf("added exact destinations = %q, want %q", strings.Join(added, ","), want)
	}
}

func runInvariantRuntimeDnsRebindingAuthority(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSettingsJSON(mustHooksConfigMap(t, agent.NewClaudeAgent(), "sir", "guard"))
	shadowHome := t.TempDir()

	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:                 string(agent.Claude),
		Mode:                    runContainmentModeDarwinProxy,
		ProxyURL:                "http://127.0.0.1:39999",
		SOCKSProxyURL:           "socks5://127.0.0.1:40000",
		ProxyProtocols:          []string{"http-connect", "socks5"},
		AllowedHosts:            []string{"api.anthropic.com", "localhost"},
		AllowedDestinations:     []string{"api.anthropic.com:443", "localhost:*"},
		AllowedHostCount:        2,
		AllowedDestinationCount: 2,
		ShadowStateHome:         shadowHome,
		StartedAt:               time.Now().Add(-time.Minute),
		HeartbeatAt:             time.Now(),
	}); err != nil {
		t.Fatalf("save launch runtime: %v", err)
	}
	t.Cleanup(func() { _ = session.RemoveRuntimeContainment(env.projectRoot) })

	// Simulate a post-launch resolver drift source by replacing the current
	// lease after the runtime descriptor has already been recorded.
	driftedLease := lease.DefaultLease()
	driftedLease.ApprovedHosts = []string{"resolver-drift.example.invalid"}
	if err := driftedLease.Save(filepath.Join(session.DurableStateDir(env.projectRoot), "lease.json")); err != nil {
		t.Fatalf("save drifted lease: %v", err)
	}

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"runtime   degraded (claude via darwin_local_proxy)",
		fixture.Expected["status_contains"],
	} {
		if want != "" && !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, driftedLease.ApprovedHosts[0]) {
		t.Fatalf("status output unexpectedly reflected post-launch drift:\n%s", out)
	}
}
