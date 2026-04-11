package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantSecretReadThenEgress(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	forceLocalPolicyFallbackForCLI(t)

	env := newTestEnv(t)
	l := env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	env.writeSession(state)

	if err := os.WriteFile(filepath.Join(env.projectRoot, fixture.SensitivePath), []byte(fixture.ReadOutput), 0o600); err != nil {
		t.Fatalf("write sensitive file: %v", err)
	}

	readResp, err := hooks.ExportEvaluatePayload(&hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": fixture.SensitivePath},
	}, l, state, env.projectRoot)
	if err != nil {
		t.Fatalf("evaluate sensitive read: %v", err)
	}
	if got, want := string(readResp.Decision), fixture.Expected["read_decision"]; got != want {
		t.Fatalf("read decision = %q, want %q", got, want)
	}

	if _, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:   "Read",
		ToolInput:  map[string]interface{}{"file_path": fixture.SensitivePath},
		ToolOutput: fixture.ReadOutput,
	}, l, state, env.projectRoot); err != nil {
		t.Fatalf("post-evaluate sensitive read: %v", err)
	}

	egressResp, err := hooks.ExportEvaluatePayload(&hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": fixture.EgressCommand},
	}, l, state, env.projectRoot)
	if err != nil {
		t.Fatalf("evaluate egress: %v", err)
	}
	if got, want := string(egressResp.Decision), fixture.Expected["egress_decision"]; got != want {
		t.Fatalf("egress decision = %q, want %q (reason=%s)", got, want, egressResp.Reason)
	}
}

func runInvariantMCPCredentialLeak(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	forceLocalPolicyFallbackForCLI(t)

	env := newTestEnv(t)
	l := env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	env.writeSession(state)

	resp, err := hooks.ExportEvaluatePayload(&hooks.HookPayload{
		ToolName:  fixture.ToolName,
		ToolInput: fixture.ToolInput,
	}, l, state, env.projectRoot)
	if err != nil {
		t.Fatalf("evaluate MCP credential leak: %v", err)
	}
	if got, want := string(resp.Decision), fixture.Expected["decision"]; got != want {
		t.Fatalf("MCP credential leak decision = %q, want %q (reason=%s)", got, want, resp.Reason)
	}

	entries, err := ledger.ReadAll(env.projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry for MCP credential leak")
	}
	last := entries[len(entries)-1]
	if got, want := last.Verb, fixture.Expected["verb"]; got != want {
		t.Fatalf("ledger verb = %q, want %q", got, want)
	}
}

func loadInvariantToolOutputFixture(t *testing.T, fixture securityInvariantFixture) string {
	t.Helper()
	if fixture.ToolOutput != "" {
		return fixture.ToolOutput
	}
	if fixture.ToolOutputFixture == "" {
		t.Fatal("fixture is missing tool_output or tool_output_fixture")
	}

	root := repoRoot(t)
	path := filepath.Clean(filepath.Join(root, "testdata", "security-invariants", "v1", fixture.ToolOutputFixture))
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read tool output fixture %s: %v", path, err)
	}
	var payload struct {
		ToolOutput string `json:"tool_output"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("unmarshal tool output fixture %s: %v", path, err)
	}
	if payload.ToolOutput == "" {
		t.Fatalf("tool output fixture %s missing tool_output", path)
	}
	return payload.ToolOutput
}

func runInvariantMCPResponseMiddleWindowInjection(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	forceLocalPolicyFallbackForCLI(t)

	env := newTestEnv(t)
	l := env.writeDefaultLease()
	state := session.NewState(env.projectRoot)
	env.writeSession(state)

	payload := &hooks.PostHookPayload{
		ToolName:   fixture.ToolName,
		ToolInput:  fixture.ToolInput,
		ToolOutput: loadInvariantToolOutputFixture(t, fixture),
	}

	resp, err := hooks.ExportPostEvaluatePayload(payload, l, state, env.projectRoot)
	if err != nil {
		t.Fatalf("post-evaluate middle-window injection: %v", err)
	}
	if got, want := string(resp.Decision), fixture.Expected["decision"]; got != want {
		t.Fatalf("middle-window injection decision = %q, want %q (reason=%s)", got, want, resp.Reason)
	}

	if got, want := string(state.Posture), fixture.Expected["posture"]; got != want {
		t.Fatalf("posture = %q, want %q", got, want)
	}
	if !state.PendingInjectionAlert {
		t.Fatal("expected PendingInjectionAlert after middle-window injection")
	}
	if !state.IsMCPServerTainted(fixture.Expected["server"]) {
		t.Fatalf("expected %q to be tainted", fixture.Expected["server"])
	}
}

func runInvariantHookTamperRestore(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()

	env := newTestEnv(t)
	l := env.writeDefaultLease()

	ag := agent.ForID(agent.AgentID(fixture.TamperedAgent))
	if ag == nil {
		t.Fatalf("unknown tampered agent %q", fixture.TamperedAgent)
	}
	spec := ag.GetSpec()
	if spec == nil {
		t.Fatalf("agent %q missing spec", fixture.TamperedAgent)
	}

	builder, ok := ag.(agent.MapBuilder)
	if !ok {
		t.Fatalf("agent %q does not implement MapBuilder", fixture.TamperedAgent)
	}
	liveConfig := mustHooksConfigMap(t, builder, "sir", l.Mode)
	env.writeSettingsJSON(liveConfig)

	canonicalPath := spec.ConfigStrategy.CanonicalBackupPath(env.home)
	if err := os.MkdirAll(filepath.Dir(canonicalPath), 0o700); err != nil {
		t.Fatalf("mkdir canonical path: %v", err)
	}
	canonicalRaw, err := json.MarshalIndent(liveConfig, "", "  ")
	if err != nil {
		t.Fatalf("marshal canonical config: %v", err)
	}
	if err := os.WriteFile(canonicalPath, canonicalRaw, 0o600); err != nil {
		t.Fatalf("write canonical config: %v", err)
	}

	state := session.NewState(env.projectRoot)
	state.PostureHashes = posture.HashSentinelFiles(env.projectRoot, l.PostureFiles)
	globalHash, err := posture.HashGlobalHooks(env.projectRoot)
	if err != nil {
		t.Fatalf("hash global hooks: %v", err)
	}
	state.GlobalHookHash = globalHash
	env.writeSession(state)

	env.writeSettingsJSON(map[string]interface{}{
		"hooks": map[string]interface{}{
			"PreToolUse": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": "evil guard evaluate",
						},
					},
				},
			},
		},
	})

	resp, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "true"},
	}, l, state, env.projectRoot)
	if err != nil {
		t.Fatalf("post-evaluate tamper: %v", err)
	}
	if got, want := string(resp.Decision), fixture.Expected["decision"]; got != want {
		t.Fatalf("tamper decision = %q, want %q (reason=%s)", got, want, resp.Reason)
	}
	if !state.DenyAll {
		t.Fatal("expected deny-all after hook tamper restore")
	}

	restored, err := os.ReadFile(filepath.Join(env.home, spec.ConfigFile))
	if err != nil {
		t.Fatalf("read restored hook file: %v", err)
	}
	if strings.Contains(string(restored), "evil guard evaluate") {
		t.Fatalf("hook file was not restored:\n%s", restored)
	}

	entries, err := ledger.ReadAll(env.projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected ledger entry for hook tamper")
	}
	last := entries[len(entries)-1]
	if got, want := last.AlertType, fixture.Expected["alert_type"]; got != want {
		t.Fatalf("ledger alert_type = %q, want %q", got, want)
	}
	if got, want := last.Agent, fixture.Expected["agent_id"]; got != want {
		t.Fatalf("ledger agent_id = %q, want %q", got, want)
	}
}

func runInvariantManagedModeRefusal(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()

	env := newTestEnv(t)
	writeManagedPolicyForEnv(t, env, lease.DefaultLease())

	err := ensureManagedCommandAllowed(fixture.DisabledCommand)
	if err == nil {
		t.Fatalf("expected %s to be blocked by managed mode", fixture.DisabledCommand)
	}
	if !strings.Contains(err.Error(), fixture.Expected["error_contains"]) {
		t.Fatalf("managed mode error = %q, want substring %q", err.Error(), fixture.Expected["error_contains"])
	}
}

func runInvariantLineagePushDenial(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	forceLocalPolicyFallbackForCLI(t)

	env := newTestEnv(t)
	projectRoot := env.projectRoot
	initInvariantGitRepo(t, projectRoot)

	l := env.writeDefaultLease()
	state := session.NewState(projectRoot)
	env.writeSession(state)

	if err := os.WriteFile(filepath.Join(projectRoot, fixture.SensitivePath), []byte("OPENAI_API_KEY=sk-secret"), 0o600); err != nil {
		t.Fatalf("write sensitive file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, fixture.DerivedPath), []byte("copied secret"), 0o644); err != nil {
		t.Fatalf("write derived file: %v", err)
	}

	if _, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": fixture.SensitivePath},
	}, l, state, projectRoot); err != nil {
		t.Fatalf("post-evaluate read: %v", err)
	}
	if err := state.Save(); err != nil {
		t.Fatalf("save state after read: %v", err)
	}
	if _, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": fixture.DerivedPath},
	}, l, state, projectRoot); err != nil {
		t.Fatalf("post-evaluate write: %v", err)
	}

	state.IncrementTurn()
	if err := state.Save(); err != nil {
		t.Fatalf("save state after turn increment: %v", err)
	}
	reloaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}

	runInvariantGit(t, projectRoot, "add", fixture.DerivedPath)
	runInvariantGit(t, projectRoot, "commit", "-m", "add derived file")

	resp, err := hooks.ExportEvaluatePayload(&hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": fixture.PushCommand},
	}, l, reloaded, projectRoot)
	if err != nil {
		t.Fatalf("evaluate push: %v", err)
	}
	if got, want := string(resp.Decision), fixture.Expected["decision"]; got != want {
		t.Fatalf("push decision = %q, want %q (reason=%s)", got, want, resp.Reason)
	}
}
