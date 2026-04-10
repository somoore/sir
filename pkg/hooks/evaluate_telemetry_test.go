package hooks

import (
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
