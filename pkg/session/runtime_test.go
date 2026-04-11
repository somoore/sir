package session

import (
	"encoding/json"
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

func TestInspectRuntimeContainmentFallsBackToLastReceipt(t *testing.T) {
	projectRoot := t.TempDir()
	info := &RuntimeContainment{
		AgentID:                 "claude",
		Mode:                    "darwin_local_proxy",
		AllowedHostCount:        2,
		AllowedDestinationCount: 4,
		AllowedEgressCount:      3,
		BlockedEgressCount:      1,
		LastBlockedDestination:  "api.example.com:443",
		StartedAt:               time.Now().Add(-time.Minute),
		EndedAt:                 time.Now().Add(-30 * time.Second),
		ExitCode:                0,
	}
	if err := SaveLastRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveLastRuntimeContainment: %v", err)
	}

	inspection, err := InspectRuntimeContainment(projectRoot, time.Now())
	if err != nil {
		t.Fatalf("InspectRuntimeContainment: %v", err)
	}
	if inspection == nil || inspection.Health != RuntimeContainmentInactive {
		t.Fatalf("expected inactive inspection, got %+v", inspection)
	}
	if inspection.Info == nil || inspection.Info.AllowedEgressCount != 3 || inspection.Info.BlockedEgressCount != 1 {
		t.Fatalf("unexpected inactive receipt: %+v", inspection)
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

func TestSaveAndLoadLastRuntimeContainment(t *testing.T) {
	projectRoot := t.TempDir()
	info := &RuntimeContainment{
		AgentID:                 "gemini",
		Mode:                    "linux_network_namespace_allowlist",
		AllowedHostCount:        3,
		AllowedDestinationCount: 9,
		AllowedEgressCount:      5,
		BlockedEgressCount:      2,
		LastBlockedDestination:  "api.example.com:443",
		ExitCode:                17,
		StartedAt:               time.Now().Add(-time.Minute).UTC().Truncate(time.Second),
		EndedAt:                 time.Now().UTC().Truncate(time.Second),
	}
	if err := SaveLastRuntimeContainment(projectRoot, info); err != nil {
		t.Fatalf("SaveLastRuntimeContainment: %v", err)
	}

	reloaded, err := LoadLastRuntimeContainment(projectRoot)
	if err != nil {
		t.Fatalf("LoadLastRuntimeContainment: %v", err)
	}
	if reloaded.AgentID != info.AgentID || reloaded.Mode != info.Mode {
		t.Fatalf("unexpected last receipt identity: %+v", reloaded)
	}
	if reloaded.AllowedEgressCount != info.AllowedEgressCount || reloaded.BlockedEgressCount != info.BlockedEgressCount {
		t.Fatalf("unexpected last receipt counters: %+v", reloaded)
	}
	if reloaded.LastBlockedDestination != info.LastBlockedDestination || reloaded.ExitCode != info.ExitCode {
		t.Fatalf("unexpected last receipt details: %+v", reloaded)
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

func TestLoadStateForRuntimeInspectionUsesShadowState(t *testing.T) {
	projectRoot := t.TempDir()

	ambient := NewState(projectRoot)
	ambient.SessionID = "ambient-session"
	if err := ambient.Save(); err != nil {
		t.Fatalf("ambient Save: %v", err)
	}

	shadowHome := t.TempDir()
	shadow := NewState(projectRoot)
	shadow.SessionID = "shadow-session"
	data, err := json.MarshalIndent(shadow, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(StatePathUnder(shadowHome, projectRoot)), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(StatePathUnder(shadowHome, projectRoot), data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	inspection := &RuntimeContainmentInspection{
		Health: RuntimeContainmentActive,
		Info: &RuntimeContainment{
			ShadowStateHome: shadowHome,
		},
	}

	state, stateDir, err := LoadStateForRuntimeInspection(projectRoot, inspection)
	if err != nil {
		t.Fatalf("LoadStateForRuntimeInspection: %v", err)
	}
	if state.SessionID != "shadow-session" {
		t.Fatalf("session id = %q, want shadow-session", state.SessionID)
	}
	if stateDir != StateDirUnder(shadowHome, projectRoot) {
		t.Fatalf("state dir = %q, want %q", stateDir, StateDirUnder(shadowHome, projectRoot))
	}
}

func TestLoadStateForRuntimeInspectionFallsBackToAmbientState(t *testing.T) {
	projectRoot := t.TempDir()
	state := NewState(projectRoot)
	state.SessionID = "ambient-session"
	if err := state.Save(); err != nil {
		t.Fatalf("Save: %v", err)
	}

	inspection := &RuntimeContainmentInspection{
		Health: RuntimeContainmentStale,
		Info: &RuntimeContainment{
			ShadowStateHome: t.TempDir(),
		},
	}

	loaded, stateDir, err := LoadStateForRuntimeInspection(projectRoot, inspection)
	if err != nil {
		t.Fatalf("LoadStateForRuntimeInspection: %v", err)
	}
	if loaded.SessionID != "ambient-session" {
		t.Fatalf("session id = %q, want ambient-session", loaded.SessionID)
	}
	if stateDir != StateDir(projectRoot) {
		t.Fatalf("state dir = %q, want %q", stateDir, StateDir(projectRoot))
	}
}

func TestRuntimeContainmentInspectionFixesForMaskedHostControl(t *testing.T) {
	inspection := &RuntimeContainmentInspection{
		Health: RuntimeContainmentDegraded,
		Info: &RuntimeContainment{
			AgentID:           "claude",
			Mode:              "linux_network_namespace_allowlist",
			ScrubbedEnvVars:   []string{"B_VAR", "A_VAR"},
			MaskedHostSockets: []string{"/tmp/ssh-agent.sock", "/private/tmp/ssh-agent.sock"},
		},
	}

	if got, want := inspection.Warning(), "launch inherited host-control bridges that sir had to mask or scrub"; got != want {
		t.Fatalf("Warning() = %q, want %q", got, want)
	}
	if got, want := inspection.Impact(), "host control channels were present at launch; relaunch from a cleaner environment for the strongest boundary"; got != want {
		t.Fatalf("Impact() = %q, want %q", got, want)
	}

	fixes := inspection.Fixes()
	if len(fixes) != 2 {
		t.Fatalf("Fixes() = %v, want 2 fixes", fixes)
	}
	if fixes[0] != "relaunch from a minimal env, for example: env -u A_VAR -u B_VAR sir run claude" {
		t.Fatalf("first fix = %q", fixes[0])
	}
	if fixes[1] != "close or avoid forwarding host-control bridges before launch: ssh-agent.sock" {
		t.Fatalf("second fix = %q", fixes[1])
	}
}

func TestRuntimeContainmentMinimalEnvCommandDefaults(t *testing.T) {
	if got := (*RuntimeContainment)(nil).MinimalEnvCommand(); got != "sir run <agent>" {
		t.Fatalf("nil MinimalEnvCommand() = %q", got)
	}
	if got := (&RuntimeContainment{}).MinimalEnvCommand(); got != "sir run <agent>" {
		t.Fatalf("empty MinimalEnvCommand() = %q", got)
	}
}
