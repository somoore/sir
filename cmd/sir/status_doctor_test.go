package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/session"
	"github.com/somoore/sir/pkg/telemetry"
)

// -------------------------------------------------------------------
// cmdStatus tests (output-based, we just verify it doesn't crash)
// -------------------------------------------------------------------

func TestCmdStatus_NotInstalled(t *testing.T) {
	env := newTestEnv(t)
	// Write settings without sir hooks
	env.writeSettingsJSON(map[string]interface{}{})

	// Should not panic
	cmdStatus(env.projectRoot)
}

func TestCmdStatus_InstalledWithSession(t *testing.T) {
	env := newTestEnv(t)

	// Write settings with sir hooks
	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	// Write lease and session
	env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	env.writeSession(state)

	// Should not panic
	cmdStatus(env.projectRoot)
}

func TestCmdStatus_SecretSession(t *testing.T) {
	env := newTestEnv(t)

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	state.MarkSecretSession()
	env.writeSession(state)

	// Should not panic and should display secret status
	cmdStatus(env.projectRoot)
}

func TestCmdStatus_DenyAll(t *testing.T) {
	env := newTestEnv(t)

	settings := map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "sir guard evaluate",
						},
					},
				},
			},
		},
	}
	env.writeSettingsJSON(settings)

	env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	state.SetDenyAll("posture tamper detected")
	env.writeSession(state)

	cmdStatus(env.projectRoot)
}

func TestCmdStatus_SupportManifestSuffixes(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	writeAgentConfig := func(ag agent.Agent, rel string) {
		t.Helper()
		builder, ok := ag.(agent.MapBuilder)
		if !ok {
			t.Fatalf("%s does not implement MapBuilder", ag.ID())
		}
		data, err := json.MarshalIndent(mustHooksConfigMap(t, builder, "sir", "standard"), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(env.home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	writeAgentConfig(agent.NewClaudeAgent(), filepath.Join(".claude", "settings.json"))
	writeAgentConfig(agent.NewGeminiAgent(), filepath.Join(".gemini", "settings.json"))
	writeAgentConfig(agent.NewCodexAgent(), filepath.Join(".codex", "hooks.json"))

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})

	for _, want := range []string{
		"(reference support)",
		"(near-parity support)",
		"(limited support, Bash-only)",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdStatus_ReportsMCPRuntimeModes(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	origLookPath := execLookPath
	execLookPath = func(file string) (string, error) {
		if file == "unshare" {
			return "/usr/bin/unshare", nil
		}
		return "", errors.New("unexpected lookup")
	}
	t.Cleanup(func() { execLookPath = origLookPath })

	claudeConfig := mustHooksConfigMap(t, agent.NewClaudeAgent(), "sir", "guard")
	claudeConfig["mcpServers"] = map[string]interface{}{
		"raw-server": map[string]interface{}{
			"command": "node",
			"args":    []string{"raw.js"},
		},
		"strict-proxy": map[string]interface{}{
			"command": "sir",
			"args":    []string{"mcp-proxy", "node", "strict.js"},
		},
		"degraded-proxy": map[string]interface{}{
			"command": "sir",
			"args":    []string{"mcp-proxy", "--allow-host", "api.slack.com", "node", "degraded.js"},
		},
	}
	env.writeSettingsJSON(claudeConfig)

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})

	if !strings.Contains(out, "  MCP:") {
		t.Fatalf("status output missing MCP section:\n%s", out)
	}
	for _, tc := range []struct {
		name  string
		proxy mcpProxySpec
	}{
		{name: "raw-server"},
		{name: "strict-proxy", proxy: mcpProxySpec{Wrapped: true}},
		{name: "degraded-proxy", proxy: mcpProxySpec{Wrapped: true, AllowedHosts: []string{"api.slack.com"}}},
	} {
		assessment := assessMCPProxyRuntime(tc.proxy, runtime.GOOS, true)
		if !strings.Contains(out, tc.name) || !strings.Contains(out, assessment.Summary) {
			t.Fatalf("status output missing %s summary %q:\n%s", tc.name, assessment.Summary, out)
		}
	}
}

func TestCmdStatus_ReportsOperabilityHealth(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	state.RecordLineageEvidence("tool_output", "Read:.env", "high", []session.LineageLabel{{
		Sensitivity: "secret",
		Trust:       "trusted",
		Provenance:  "user",
	}})
	state.AttachActiveEvidenceToPath("debug.txt")
	env.writeSession(state)

	data, err := json.MarshalIndent(&telemetry.Health{
		SchemaVersion:      1,
		EndpointConfigured: true,
		QueueSize:          32,
		WorkerCount:        2,
		QueuedCount:        12,
		DroppedCount:       1,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(telemetry.HealthPath(env.projectRoot)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telemetry.HealthPath(env.projectRoot), data, 0o600); err != nil {
		t.Fatal(err)
	}

	settings := mustHooksConfigMap(t, agent.NewClaudeAgent(), "sir", "guard")
	env.writeSettingsJSON(settings)

	out := captureStdout(t, func() {
		cmdStatus(env.projectRoot)
	})
	for _, want := range []string{
		"telemetry on (queue 32 x 2, queued 12, dropped 1)",
		"lineage   1 active evidence, 1 derived paths",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output missing %q:\n%s", want, out)
		}
	}
}

// -------------------------------------------------------------------
// cmdDoctor tests
// -------------------------------------------------------------------

func TestCmdDoctor_NoSession(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()

	// Create required posture files so SessionStart doesn't fail
	for _, f := range []string{".claude/hooks/hooks.json", ".claude/settings.json", "CLAUDE.md", ".mcp.json"} {
		dir := filepath.Join(env.projectRoot, filepath.Dir(f))
		os.MkdirAll(dir, 0o755)
		os.WriteFile(filepath.Join(env.projectRoot, f), []byte("{}"), 0o644)
	}

	// Should create a new session
	cmdDoctor(env.projectRoot)

	// Verify session was created
	state, err := session.Load(env.projectRoot)
	if err != nil {
		t.Fatal("expected session to be created by doctor")
	}
	if state.SessionID == "" {
		t.Error("expected non-empty session ID")
	}
}

func TestCmdDoctor_NoSessionReportsMCPRuntimeWarnings(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"raw-server": map[string]interface{}{
				"command": "node",
				"args":    []string{"raw.js"},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})

	rawAssessment := assessMCPProxyRuntime(mcpProxySpec{}, runtime.GOOS, hasUnshareBinary())
	if !strings.Contains(out, "WARNING: MCP raw-server in ~/.claude/settings.json is "+rawAssessment.Summary) {
		t.Fatalf("doctor no-session path missing MCP warning:\n%s", out)
	}
}

func TestCmdDoctor_ClearsDenyAll(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()

	state := session.NewState(env.projectRoot)
	state.SetDenyAll("test reason")
	env.writeSession(state)

	cmdDoctor(env.projectRoot)

	reloaded, err := session.Load(env.projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.DenyAll {
		t.Error("expected DenyAll to be cleared after doctor")
	}
}

func TestCmdDoctor_CodexFeatureFlagWarningUsesManifest(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	data, err := json.MarshalIndent(mustHooksConfigMap(t, agent.NewCodexAgent(), "sir", "standard"), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	codexHooksPath := filepath.Join(env.home, ".codex", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(codexHooksPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexHooksPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.home, ".codex", "config.toml"), []byte("[features]\nexperimental = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})

	if !strings.Contains(out, "codex_hooks=true is NOT set under [features]") {
		t.Fatalf("doctor output missing codex feature-flag warning:\n%s", out)
	}
	if !strings.Contains(out, "Fix: codex features enable codex_hooks") {
		t.Fatalf("doctor output missing codex feature-flag remediation:\n%s", out)
	}
}

func TestCmdDoctor_ReportsOperabilityWarnings(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	for i := 0; i < lineageWarnDerivedPaths+1; i++ {
		state.RecordLineageEvidence("tool_output", "Read:.env", "high", []session.LineageLabel{{
			Sensitivity: "secret",
			Trust:       "trusted",
			Provenance:  "user",
		}})
		state.AttachActiveEvidenceToPath(filepath.Join(env.projectRoot, "derived", fmt.Sprintf("file-%03d.txt", i)))
	}
	env.writeSession(state)

	data, err := json.MarshalIndent(&telemetry.Health{
		SchemaVersion:      1,
		EndpointConfigured: true,
		QueueSize:          32,
		WorkerCount:        2,
		QueuedCount:        10,
		DroppedCount:       4,
	}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(telemetry.HealthPath(env.projectRoot)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(telemetry.HealthPath(env.projectRoot), data, 0o600); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	for _, want := range []string{
		"WARNING: telemetry dropped 4 event(s)",
		"Fix: verify collector reachability or unset SIR_OTLP_ENDPOINT",
		"WARNING: derived lineage tracks",
		"Fix: finish the current task, then start a fresh agent session",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdDoctor_PrunesStaleRuntimeContainment(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	shadowStateHome := filepath.Join(t.TempDir(), "sir-run-state-missing")
	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:         string(agent.Claude),
		Mode:            "linux_network_namespace_allowlist",
		ShadowStateHome: shadowStateHome,
		StartedAt:       time.Now().Add(-time.Minute),
		HeartbeatAt:     time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	if !strings.Contains(out, "Cleared: stale runtime containment") {
		t.Fatalf("doctor output missing stale runtime cleanup:\n%s", out)
	}
	if inspection, err := inspectRuntimeContainment(env.projectRoot); err != nil {
		t.Fatalf("inspectRuntimeContainment: %v", err)
	} else if inspection != nil {
		t.Fatalf("expected stale runtime containment to be pruned, got %#v", inspection)
	}
}

func TestCmdDoctor_ReportsDegradedRuntimeContainment(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	shadowHome := t.TempDir()
	shadowState := session.NewState(env.projectRoot)
	data, err := json.MarshalIndent(shadowState, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(session.StatePathUnder(shadowHome, env.projectRoot)), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(session.StatePathUnder(shadowHome, env.projectRoot), data, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := session.SaveRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:           string(agent.Claude),
		Mode:              "darwin_local_proxy",
		ShadowStateHome:   shadowHome,
		StartedAt:         time.Now().Add(-time.Minute),
		HeartbeatAt:       time.Now(),
		ScrubbedEnvVars:   []string{"SSH_AUTH_SOCK"},
		MaskedHostSockets: []string{"/tmp/ssh-agent.sock"},
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	for _, want := range []string{
		"WARNING: runtime containment is degraded",
		"Fix: prefer Linux exact-destination containment for the strongest below-hook boundary.",
		"Fix: relaunch from a minimal env, for example: env -u SSH_AUTH_SOCK sir run claude.",
		"Fix: close or avoid forwarding host-control bridges before launch: ssh-agent.sock.",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("doctor output missing %q:\n%s", want, out)
		}
	}
}

func TestCmdDoctor_ReportsLastRuntimeReceipt(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	if err := session.SaveLastRuntimeContainment(env.projectRoot, &session.RuntimeContainment{
		AgentID:            string(agent.Claude),
		Mode:               "darwin_local_proxy",
		AllowedEgressCount: 4,
		BlockedEgressCount: 1,
		ExitCode:           0,
		EndedAt:            time.Date(2026, time.April, 10, 20, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})
	if !strings.Contains(out, "runtime last launch: claude via darwin_local_proxy exited 0 (4 allowed / 1 blocked)") {
		t.Fatalf("doctor output missing last runtime receipt:\n%s", out)
	}
}

func TestCmdDoctor_ReportsMCPRuntimeWarnings(t *testing.T) {
	env := newTestEnv(t)
	env.writeDefaultLease()
	env.writeSession(session.NewState(env.projectRoot))

	origLookPath := execLookPath
	execLookPath = func(file string) (string, error) {
		if file == "unshare" {
			return "/usr/bin/unshare", nil
		}
		return "", errors.New("unexpected lookup")
	}
	t.Cleanup(func() { execLookPath = origLookPath })

	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"raw-server": map[string]interface{}{
				"command": "node",
				"args":    []string{"raw.js"},
			},
			"strict-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "node", "strict.js"},
			},
			"degraded-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "--allow-host", "api.slack.com", "node", "degraded.js"},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdDoctor(env.projectRoot)
	})

	rawAssessment := assessMCPProxyRuntime(mcpProxySpec{}, runtime.GOOS, true)
	if !strings.Contains(out, "WARNING: MCP raw-server in ~/.claude/settings.json is "+rawAssessment.Summary) {
		t.Fatalf("doctor output missing raw MCP warning:\n%s", out)
	}

	degradedAssessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true, AllowedHosts: []string{"api.slack.com"}}, runtime.GOOS, true)
	if !strings.Contains(out, "WARNING: MCP degraded-proxy in ~/.claude/settings.json is "+degradedAssessment.Summary) {
		t.Fatalf("doctor output missing degraded MCP warning:\n%s", out)
	}

	strictAssessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true}, runtime.GOOS, true)
	if !strings.Contains(out, "[ok] MCP strict-proxy in ~/.claude/settings.json: "+strictAssessment.Summary) {
		t.Fatalf("doctor output missing strict MCP ok line:\n%s", out)
	}
}

// -------------------------------------------------------------------
