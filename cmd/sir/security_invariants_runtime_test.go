package main

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	runtimepkg "github.com/somoore/sir/pkg/runtime"
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
