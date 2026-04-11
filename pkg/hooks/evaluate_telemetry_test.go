package hooks

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func TestAppendEvaluationLedgerEntry_EmitsTelemetryWhenLedgerAppendFails(t *testing.T) {
	projectRoot := t.TempDir()
	blockedHome := filepath.Join(t.TempDir(), "state-home-file")
	if err := os.WriteFile(blockedHome, []byte("not-a-directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(session.StateHomeEnvVar, blockedHome)

	var (
		mu   sync.Mutex
		body string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("SIR_OTLP_ENDPOINT", srv.URL)

	state := session.NewState(projectRoot)
	appendEvaluationLedgerEntry(
		projectRoot,
		&HookPayload{ToolName: "Bash", ToolInput: map[string]interface{}{"command": "curl https://evil.example"}},
		Intent{Verb: policy.VerbNetExternal, Target: "https://evil.example"},
		core.Label{Sensitivity: "public", Trust: "trusted", Provenance: "user"},
		policy.VerdictDeny,
		"test deny",
		state,
		agent.NewClaudeAgent(),
	)

	mu.Lock()
	got := body
	mu.Unlock()
	if !strings.Contains(got, "\"sir.verdict\"") || !strings.Contains(got, "deny") {
		t.Fatalf("expected telemetry payload despite ledger failure, got %q", got)
	}
	if !strings.Contains(got, "\"sir.reason\"") || !strings.Contains(got, "test deny") {
		t.Fatalf("expected deny reason in telemetry payload, got %q", got)
	}
}

func TestEvaluatePayload_DelegationDenyLogsLedgerAndTelemetry(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.AllowDelegation = false

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}

	var (
		mu   sync.Mutex
		body string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("SIR_OTLP_ENDPOINT", srv.URL)

	resp, err := evaluatePayload(&HookPayload{
		ToolName:  "Agent",
		ToolInput: map[string]interface{}{"task": "delegate work to a sub-agent"},
		CWD:       projectRoot,
	}, l, state, projectRoot, agent.NewClaudeAgent())
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != policy.VerdictDeny {
		t.Fatalf("evaluatePayload decision = %q, want %q (reason=%s)", resp.Decision, policy.VerdictDeny, resp.Reason)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected delegation deny to be written to the ledger")
	}
	last := entries[len(entries)-1]
	if last.Decision != string(policy.VerdictDeny) {
		t.Fatalf("ledger decision = %q, want %q", last.Decision, policy.VerdictDeny)
	}
	if !strings.Contains(last.Reason, "allow_delegation = false") {
		t.Fatalf("ledger reason = %q, want delegation deny reason", last.Reason)
	}

	mu.Lock()
	got := body
	mu.Unlock()
	if !strings.Contains(got, "\"sir.verdict\"") || !strings.Contains(got, "deny") {
		t.Fatalf("expected delegation deny telemetry payload, got %q", got)
	}
}

func TestEvaluateSubagentStart_DelegationAskLogsLedgerAndTelemetry(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()

	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state: %v", err)
	}
	if err := l.Save(stateDir + "/lease.json"); err != nil {
		t.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	state.PostureHashes = HashSentinelFiles(projectRoot, l.PostureFiles)
	state.AddTaintedMCPServer("jira")
	state.RaisePosture(policy.PostureStateCritical)
	if err := state.Save(); err != nil {
		t.Fatalf("save tainted session: %v", err)
	}

	var (
		mu   sync.Mutex
		body string
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		body = string(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("SIR_OTLP_ENDPOINT", srv.URL)

	buf, err := runSubagentStartForTest(t, projectRoot, SubagentPayload{
		HookEventName: "SubagentStart",
		AgentName:     "general-purpose",
		Tools:         []string{"Read"},
	})
	if err != nil {
		t.Fatalf("EvaluateSubagentStart: %v", err)
	}
	if len(buf) == 0 {
		t.Fatal("expected ask response from subagent delegation")
	}

	var resp struct {
		HookSpecificOutput struct {
			PermissionDecision string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(buf, &resp); err != nil {
		t.Fatalf("unmarshal response: %v\nraw: %s", err, string(buf))
	}
	if resp.HookSpecificOutput.PermissionDecision != "ask" {
		t.Fatalf("permissionDecision = %q, want ask", resp.HookSpecificOutput.PermissionDecision)
	}

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected subagent ask to be written to the ledger")
	}
	last := entries[len(entries)-1]
	if last.Decision != "ask" {
		t.Fatalf("ledger decision = %q, want ask", last.Decision)
	}

	mu.Lock()
	got := body
	mu.Unlock()
	if !strings.Contains(got, "\"sir.verdict\"") || !strings.Contains(got, "ask") {
		t.Fatalf("expected subagent ask telemetry payload, got %q", got)
	}
}
