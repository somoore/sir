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
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func TestConfigChange_TamperWritesLedgerEntry(t *testing.T) {
	projectRoot, ag := setupConfigChangeTamperEnv(t)

	runConfigChangeEvent(t, projectRoot, ag)

	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatalf("expected config change plus tamper entry, got %d", len(entries))
	}
	last := entries[len(entries)-1]
	if last.AlertType != "hook_tamper" {
		t.Fatalf("expected hook_tamper alert, got %q", last.AlertType)
	}
	if last.Agent != "claude" {
		t.Fatalf("expected tampered agent claude, got %q", last.Agent)
	}
	if !last.Restored {
		t.Fatal("expected auto-restore status to be recorded")
	}
	if last.DiffSummary == "" {
		t.Fatal("expected diff summary")
	}
	if !strings.Contains(last.DiffSummary, "PreToolUse") && !strings.Contains(last.DiffSummary, "Stop") {
		t.Fatalf("expected diff summary to mention changed hook keys, got %q", last.DiffSummary)
	}
}

func TestConfigChange_TamperEmitsOTLP(t *testing.T) {
	projectRoot, ag := setupConfigChangeTamperEnv(t)

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

	runConfigChangeEvent(t, projectRoot, ag)

	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(body, "\"sir.alert.type\"") || !strings.Contains(body, "hook_tamper") {
		t.Fatalf("expected hook_tamper OTLP payload, got %s", body)
	}
	if !strings.Contains(body, "\"sir.alert.agent.id\"") || !strings.Contains(body, "claude") {
		t.Fatalf("expected tampered agent id in OTLP payload, got %s", body)
	}
}

func setupConfigChangeTamperEnv(t *testing.T) (string, agent.Agent) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)

	projectRoot := t.TempDir()
	if err := os.MkdirAll(session.StateDir(projectRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".sir"), 0o755); err != nil {
		t.Fatal(err)
	}

	livePath := filepath.Join(home, ".claude", "settings.json")
	canonPath := filepath.Join(home, ".sir", "hooks-canonical.json")
	original := []byte(`{"hooks":{"PreToolUse":[{"matcher":".*","hooks":[{"command":"sir guard evaluate"}]}]}}`)
	tampered := []byte(`{"hooks":{"Stop":[{"matcher":".*","hooks":[{"command":"evil"}]}]}}`)
	if err := os.WriteFile(livePath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonPath, original, 0o600); err != nil {
		t.Fatal(err)
	}

	globalHash, err := hashGlobalHooksFile()
	if err != nil {
		t.Fatalf("hashGlobalHooksFile: %v", err)
	}

	state := session.NewState(projectRoot)
	state.GlobalHookHash = globalHash
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(livePath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	return projectRoot, agent.NewClaudeAgent()
}

func runConfigChangeEvent(t *testing.T, projectRoot string, ag agent.Agent) {
	t.Helper()
	withTestStdin(t, `{"session_id":"sess-1","hook_event_name":"ConfigChange","config_key":"hooks"}`, func() {
		if err := EvaluateConfigChange(projectRoot, ag); err != nil {
			t.Fatalf("EvaluateConfigChange: %v", err)
		}
	})
}

func withTestStdin(t *testing.T, input string, fn func()) {
	t.Helper()
	orig := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	defer func() {
		os.Stdin = orig
		_ = r.Close()
	}()
	fn()
}
