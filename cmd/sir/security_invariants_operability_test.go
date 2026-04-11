package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantRuntimeDegradationGuidance(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()

	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSettingsJSON(mustHooksConfigMap(t, agent.NewClaudeAgent(), "sir", "guard"))
	env.writeSession(session.NewState(env.projectRoot))

	shadowHome := t.TempDir()
	shadowState := session.NewState(env.projectRoot)
	shadowData, err := json.MarshalIndent(shadowState, "", "  ")
	if err != nil {
		t.Fatalf("marshal shadow session: %v", err)
	}
	shadowPath := session.StatePathUnder(shadowHome, env.projectRoot)
	if err := os.MkdirAll(filepath.Dir(shadowPath), 0o700); err != nil {
		t.Fatalf("mkdir shadow state dir: %v", err)
	}
	if err := os.WriteFile(shadowPath, shadowData, 0o600); err != nil {
		t.Fatalf("write shadow session: %v", err)
	}

	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:           string(agent.Claude),
		Mode:              "darwin_local_proxy",
		ProxyURL:          "http://127.0.0.1:7777",
		ShadowStateHome:   shadowHome,
		StartedAt:         time.Now().Add(-time.Minute),
		HeartbeatAt:       time.Now(),
		MaskedHostSockets: []string{"/tmp/ssh-agent.sock"},
		ScrubbedEnvVars:   []string{"SSH_AUTH_SOCK"},
	}); err != nil {
		t.Fatalf("save runtime containment: %v", err)
	}

	statusOut := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, key := range []string{"status_contains", "status_fix"} {
		want := fixture.Expected[key]
		if want != "" && !strings.Contains(statusOut, want) {
			t.Fatalf("status output missing %q:\n%s", want, statusOut)
		}
	}
	for _, key := range []string{"status_reason", "status_impact"} {
		want := fixture.Expected[key]
		if want != "" && !strings.Contains(statusOut, want) {
			t.Fatalf("status output missing %q:\n%s", want, statusOut)
		}
	}

	doctorOut := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	for _, key := range []string{"doctor_contains", "doctor_fix"} {
		want := fixture.Expected[key]
		if want != "" && !strings.Contains(doctorOut, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, doctorOut)
		}
	}
}
