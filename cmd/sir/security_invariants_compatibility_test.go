package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantCrossVersionStateCompatibility(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	stateDir := session.StateDir(env.projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}

	legacySession := map[string]interface{}{
		"session_id":              "legacy-session",
		"project_root":            env.projectRoot,
		"started_at":              "2026-01-01T00:00:00Z",
		"secret_session":          true,
		"recently_read_untrusted": false,
		"deny_all":                false,
		"posture_hashes":          map[string]string{},
		"lease_hash":              "legacy-lease",
		"global_hook_hash":        "legacy-hooks",
	}
	data, err := json.MarshalIndent(legacySession, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy session: %v", err)
	}
	if err := os.WriteFile(session.StatePath(env.projectRoot), data, 0o600); err != nil {
		t.Fatalf("write legacy session: %v", err)
	}

	loaded, err := session.Load(env.projectRoot)
	if err != nil {
		t.Fatalf("session.Load legacy payload: %v", err)
	}
	if !loaded.SecretSession {
		t.Fatal("expected legacy session secret flag to survive load")
	}

	legacyEntry := map[string]interface{}{
		"index":      0,
		"timestamp":  "2026-01-01T00:00:00Z",
		"prev_hash":  strings.Repeat("0", 64),
		"tool_name":  "Bash",
		"verb":       "execute_dry_run",
		"target":     "git status",
		"decision":   "allow",
		"reason":     "legacy compatibility fixture",
		"entry_hash": "",
	}
	legacyEntry["entry_hash"] = computeLegacyInvariantLedgerHash(legacyEntry)
	ledgerLine, err := json.Marshal(legacyEntry)
	if err != nil {
		t.Fatalf("marshal legacy ledger entry: %v", err)
	}
	if err := os.WriteFile(ledger.LedgerPath(env.projectRoot), append(ledgerLine, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy ledger: %v", err)
	}

	count, err := ledger.Verify(env.projectRoot)
	if err != nil {
		t.Fatalf("ledger.Verify legacy payload: %v", err)
	}
	if count != 1 {
		t.Fatalf("ledger.Verify count = %d, want 1", count)
	}
}

func runInvariantCrossVersionRuntimeCompatibility(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	shadowHome := t.TempDir()

	legacyRuntime := map[string]interface{}{
		"agent_id":          "claude",
		"mode":              "darwin_local_proxy",
		"proxy_url":         "http://127.0.0.1:7777",
		"shadow_state_home": shadowHome,
		"started_at":        "2026-01-01T00:00:00Z",
		"heartbeat_at":      time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.MarshalIndent(legacyRuntime, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy runtime: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(session.RuntimePath(env.projectRoot)), 0o700); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(session.RuntimePath(env.projectRoot), data, 0o600); err != nil {
		t.Fatalf("write legacy runtime: %v", err)
	}

	inspection, err := inspectRuntimeContainment(env.projectRoot)
	if err != nil {
		t.Fatalf("inspectRuntimeContainment legacy runtime: %v", err)
	}
	if inspection == nil {
		t.Fatal("expected runtime inspection for legacy descriptor")
	}
	if got, want := string(inspection.Health), fixture.Expected["health"]; got != want {
		t.Fatalf("runtime health = %q, want %q", got, want)
	}
	if got := strings.Join(inspection.Info.EffectiveProxyProtocols(), ","); got != fixture.Expected["proxy_protocols"] {
		t.Fatalf("effective proxy protocols = %q, want %q", got, fixture.Expected["proxy_protocols"])
	}
}
