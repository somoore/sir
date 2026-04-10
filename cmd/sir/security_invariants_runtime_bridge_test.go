package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/session"
)

func runInvariantRuntimeBridgeDegradationCompatibility(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	shadowHome := t.TempDir()

	legacyRuntime := map[string]interface{}{
		"agent_id":            "claude",
		"mode":                "linux_network_namespace_allowlist",
		"masked_host_sockets": []string{"/tmp/ssh-agent.sock"},
		"shadow_state_home":   shadowHome,
		"started_at":          "2026-01-01T00:00:00Z",
		"heartbeat_at":        time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(legacyRuntime, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy runtime bridge fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(session.RuntimePath(env.projectRoot)), 0o700); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(session.RuntimePath(env.projectRoot), data, 0o600); err != nil {
		t.Fatalf("write legacy runtime bridge fixture: %v", err)
	}

	inspection, err := inspectRuntimeContainment(env.projectRoot)
	if err != nil {
		t.Fatalf("inspectRuntimeContainment: %v", err)
	}
	if inspection == nil {
		t.Fatal("expected runtime inspection for legacy bridge descriptor")
	}
	if got, want := string(inspection.Health), fixture.Expected["health"]; got != want {
		t.Fatalf("runtime health = %q, want %q", got, want)
	}
	if want := fixture.Expected["reason_contains"]; want != "" && !strings.Contains(inspection.Reason, want) {
		t.Fatalf("runtime degradation reason = %q, want substring %q", inspection.Reason, want)
	}
}
