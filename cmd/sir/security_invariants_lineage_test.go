package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantLineageLaunderingSurvivesSink(t *testing.T, fixture securityInvariantFixture) {
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
		t.Fatalf("post-evaluate sensitive read: %v", err)
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
	if err := state.Save(); err != nil {
		t.Fatalf("save state after write: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(projectRoot, "archive"), 0o755); err != nil {
		t.Fatalf("mkdir archive: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "renamed"), 0o755); err != nil {
		t.Fatalf("mkdir renamed: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectRoot, "linked"), 0o755); err != nil {
		t.Fatalf("mkdir linked: %v", err)
	}
	archivePath := filepath.Join(projectRoot, "archive", "report.txt")
	reportPath := filepath.Join(projectRoot, fixture.DerivedPath)
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report.txt: %v", err)
	}
	if err := os.WriteFile(archivePath, reportData, 0o644); err != nil {
		t.Fatalf("write archive copy: %v", err)
	}
	renamedPath := filepath.Join(projectRoot, "renamed", "report.txt")
	if err := os.Rename(archivePath, renamedPath); err != nil {
		t.Fatalf("rename archive copy: %v", err)
	}
	linkedPath := filepath.Join(projectRoot, "linked", "report.txt")
	if err := os.WriteFile(linkedPath, reportData, 0o644); err != nil {
		t.Fatalf("write linked copy: %v", err)
	}

	if _, err := hooks.ExportPostEvaluatePayload(&hooks.PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": fixture.LaunderCommand},
	}, l, state, projectRoot); err != nil {
		t.Fatalf("post-evaluate laundering command: %v", err)
	}
	if err := state.Save(); err != nil {
		t.Fatalf("save state after laundering: %v", err)
	}

	if got := state.DerivedLabelsForPath(hooks.ResolveTarget(projectRoot, fixture.LaunderedPath)); len(got) == 0 {
		t.Fatalf("laundered path %q should preserve lineage, got none (tracked=%v)", fixture.LaunderedPath, state.DerivedPaths())
	}
	if _, err := os.Stat(filepath.Join(projectRoot, fixture.LaunderedPath)); err != nil {
		t.Fatalf("laundered path %q missing on disk: %v", fixture.LaunderedPath, err)
	}

	runInvariantGit(t, projectRoot, "add", "-A")
	runInvariantGit(t, projectRoot, "commit", "-m", "add laundered derived file")

	state.IncrementTurn()
	if err := state.Save(); err != nil {
		t.Fatalf("save state after turn increment: %v", err)
	}
	reloaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatalf("reload session: %v", err)
	}

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
