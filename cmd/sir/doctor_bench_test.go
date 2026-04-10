package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func BenchmarkCmdDoctorLargeState(b *testing.B) {
	homeDir := b.TempDir()
	projectRoot := b.TempDir()
	b.Setenv("HOME", homeDir)

	stateDir := filepath.Join(homeDir, ".sir", "projects", session.ProjectHash(projectRoot))
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		b.Fatalf("mkdir state dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(homeDir, ".claude"), 0o755); err != nil {
		b.Fatalf("mkdir claude dir: %v", err)
	}

	config := agent.NewClaudeAgent().GenerateHooksConfigMap("sir", "guard")
	configData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		b.Fatalf("marshal config: %v", err)
	}
	if err := os.WriteFile(filepath.Join(homeDir, ".claude", "settings.json"), configData, 0o644); err != nil {
		b.Fatalf("write settings.json: %v", err)
	}

	l := lease.DefaultLease()
	if err := l.Save(filepath.Join(stateDir, "lease.json")); err != nil {
		b.Fatalf("save lease: %v", err)
	}

	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		b.Fatalf("save session: %v", err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		b.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	origStdout := os.Stdout
	os.Stdout = devNull
	defer func() { os.Stdout = origStdout }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmdDoctor(projectRoot)
	}
}
