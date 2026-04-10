package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInspectRuntimeContainmentActive(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "linux_network_namespace_allowlist",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-10 * time.Second),
		HeartbeatAt:     time.Now(),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentActive {
		t.Fatalf("expected active inspection, got %+v", inspection)
	}
}

func TestInspectRuntimeContainmentStaleHeartbeat(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-time.Minute),
		HeartbeatAt:     time.Now().Add(-time.Minute),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentStale {
		t.Fatalf("expected stale inspection, got %+v", inspection)
	}
	if inspection.Reason != "runtime heartbeat expired" {
		t.Fatalf("unexpected stale reason: %+v", inspection)
	}
}

func TestInspectRuntimeContainmentLegacyWithoutHeartbeat(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-time.Minute),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentLegacy {
		t.Fatalf("expected legacy inspection, got %+v", inspection)
	}
	if inspection.Reason != "runtime heartbeat unavailable (legacy descriptor)" {
		t.Fatalf("unexpected legacy reason: %+v", inspection)
	}
}

func TestInspectRuntimeContainmentDegraded(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-10 * time.Second),
		HeartbeatAt:     time.Now(),
		DegradedReasons: []string{"proxy-shaped enforcement remains outside the exact-destination boundary"},
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentDegraded {
		t.Fatalf("expected degraded inspection, got %+v", inspection)
	}
	if inspection.Reason == "" {
		t.Fatalf("expected degraded reason, got %+v", inspection)
	}
}

func TestInspectRuntimeContainmentInfersDegradedFromLegacyFields(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	info := &RuntimeContainment{
		AgentID:           "claude",
		Mode:              "linux_network_namespace_allowlist",
		ShadowStateHome:   shadowHome,
		StartedAt:         time.Now().Add(-10 * time.Second),
		HeartbeatAt:       time.Now(),
		MaskedHostSockets: []string{"/tmp/ssh-agent.sock"},
		ScrubbedEnvVars:   []string{"SSH_AUTH_SOCK"},
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentDegraded {
		t.Fatalf("expected degraded inspection, got %+v", inspection)
	}
	if got := inspection.Reason; got == "" || !strings.Contains(got, "host-control sockets") {
		t.Fatalf("expected inferred degradation reason, got %+v", inspection)
	}
}

func TestTouchRuntimeContainmentUpdatesHeartbeat(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := t.TempDir()
	original := time.Now().Add(-time.Minute).UTC().Truncate(time.Second)
	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       original,
		HeartbeatAt:     original,
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	nextHeartbeat := original.Add(45 * time.Second)
	if err := TouchRuntimeContainment(projectRoot, nextHeartbeat); err != nil {
		t.Fatalf("TouchRuntimeContainment: %v", err)
	}

	reloaded, err := LoadRuntimeContainment(projectRoot)
	if err != nil {
		t.Fatalf("LoadRuntimeContainment: %v", err)
	}
	if !reloaded.HeartbeatAt.Equal(nextHeartbeat) {
		t.Fatalf("heartbeat mismatch: got %v want %v", reloaded.HeartbeatAt, nextHeartbeat)
	}
	if !reloaded.StartedAt.Equal(original) {
		t.Fatalf("started_at should be preserved: got %v want %v", reloaded.StartedAt, original)
	}
}

func TestPruneStaleRuntimeContainmentRemovesShadowState(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := filepath.Join(os.TempDir(), "sir-run-state-test-prune")
	if err := os.MkdirAll(shadowHome, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shadowHome) })

	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-time.Minute),
		HeartbeatAt:     time.Now().Add(-time.Minute),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	if err := PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
		t.Fatalf("PruneStaleRuntimeContainment: %v", err)
	}
	if _, err := os.Stat(RuntimePath(projectRoot)); !os.IsNotExist(err) {
		t.Fatalf("runtime descriptor should be removed, got %v", err)
	}
	if _, err := os.Stat(shadowHome); !os.IsNotExist(err) {
		t.Fatalf("shadow state should be removed, got %v", err)
	}
}

func TestPruneStaleRuntimeContainmentPreservesLegacyDescriptor(t *testing.T) {
	projectRoot := t.TempDir()
	shadowHome := filepath.Join(os.TempDir(), "sir-run-state-test-legacy")
	if err := os.MkdirAll(shadowHome, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shadowHome) })

	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-time.Minute),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	if err := PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
		t.Fatalf("PruneStaleRuntimeContainment: %v", err)
	}
	if _, err := os.Stat(RuntimePath(projectRoot)); err != nil {
		t.Fatalf("runtime descriptor should be preserved, got %v", err)
	}
	if _, err := os.Stat(shadowHome); err != nil {
		t.Fatalf("shadow state should be preserved, got %v", err)
	}
}

func TestPruneStaleRuntimeContainmentPreservesLiveRuntimeByPID(t *testing.T) {
	if !pidAlive(os.Getpid()) {
		t.Skip("process liveness probing unavailable on this platform")
	}

	projectRoot := t.TempDir()
	shadowHome := filepath.Join(os.TempDir(), "sir-run-state-test-live")
	if err := os.MkdirAll(shadowHome, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(shadowHome) })

	info := &RuntimeContainment{
		AgentID:         "claude",
		Mode:            "darwin_local_proxy",
		ShadowStateHome: shadowHome,
		StartedAt:       time.Now().Add(-time.Minute),
		HeartbeatAt:     time.Now().Add(-time.Minute),
		LauncherPID:     os.Getpid(),
	}
	if err := SaveRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveRuntimeContainment: %v", err)
	}

	if err := PruneStaleRuntimeContainment(projectRoot, time.Now()); err != nil {
		t.Fatalf("PruneStaleRuntimeContainment: %v", err)
	}
	if _, err := os.Stat(RuntimePath(projectRoot)); err != nil {
		t.Fatalf("runtime descriptor should be preserved for a live process, got %v", err)
	}
	if _, err := os.Stat(shadowHome); err != nil {
		t.Fatalf("shadow state should be preserved for a live process, got %v", err)
	}
}

func TestRuntimeContainmentEffectiveProxyProtocols(t *testing.T) {
	info := &RuntimeContainment{
		ProxyURL:       "http://127.0.0.1:7777",
		SOCKSProxyURL:  "socks5://127.0.0.1:8888",
		ProxyProtocols: []string{"http-connect", "socks5"},
	}
	got := info.EffectiveProxyProtocols()
	if len(got) != 2 || got[0] != "http-connect" || got[1] != "socks5" {
		t.Fatalf("EffectiveProxyProtocols() = %v", got)
	}

	legacy := (&RuntimeContainment{ProxyURL: "http://127.0.0.1:7777"}).EffectiveProxyProtocols()
	if len(legacy) != 1 || legacy[0] != "http-connect" {
		t.Fatalf("legacy EffectiveProxyProtocols() = %v", legacy)
	}
}

func TestRuntimeContainmentEffectiveDegradedReasons(t *testing.T) {
	info := &RuntimeContainment{
		Mode:              "darwin_local_proxy",
		MaskedHostSockets: []string{"/tmp/ssh-agent.sock"},
		ScrubbedEnvVars:   []string{"SSH_AUTH_SOCK"},
	}
	got := info.EffectiveDegradedReasons()
	if len(got) != 3 {
		t.Fatalf("EffectiveDegradedReasons() = %v, want 3 reasons", got)
	}
}
