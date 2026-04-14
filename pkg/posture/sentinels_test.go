package posture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePath_GlobalAgentSentinelsUseHomeDir(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	projectRoot := t.TempDir()
	tests := []struct {
		name string
		rel  string
		want string
	}{
		{
			name: ".claude/settings.json",
			rel:  ".claude/settings.json",
			want: filepath.Join(tmpHome, ".claude", "settings.json"),
		},
		{
			name: ".gemini/settings.json",
			rel:  ".gemini/settings.json",
			want: filepath.Join(tmpHome, ".gemini", "settings.json"),
		},
		{
			name: ".codex/config.toml",
			rel:  ".codex/config.toml",
			want: filepath.Join(tmpHome, ".codex", "config.toml"),
		},
		{
			name: ".codex/hooks.json",
			rel:  ".codex/hooks.json",
			want: filepath.Join(tmpHome, ".codex", "hooks.json"),
		},
		{
			name: "project file stays project-local",
			rel:  "CLAUDE.md",
			want: filepath.Join(projectRoot, "CLAUDE.md"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolvePath(projectRoot, tt.rel); got != tt.want {
				t.Fatalf("ResolvePath(%q) = %q, want %q", tt.rel, got, tt.want)
			}
		})
	}
}

// TestHashSentinelFiles_AgentSettingsHashOnlyHooksSubtree pins the v0.0.6
// fix for the gemini-trip-on-oauth-refresh bug. Agent settings files
// (claude / gemini / codex) get re-written by the agent itself during a
// session for unrelated metadata (OAuth refresh, account state, session
// telemetry). Without subtree-only hashing, those writes trip
// posture-tamper detection and lock the session into deny-all even
// though the agent's hooks subtree is unchanged.
func TestHashSentinelFiles_AgentSettingsHashOnlyHooksSubtree(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	projectRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmpHome, ".gemini"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Initial settings: hooks plus an unrelated key that the agent owns.
	initial := `{
  "hooks": {
    "BeforeTool": [
      {
        "hooks": [
          {"command": "/bin/sir guard evaluate", "type": "command"}
        ]
      }
    ]
  },
  "selectedAuthType": "oauth-personal"
}`
	settingsPath := filepath.Join(tmpHome, ".gemini", "settings.json")
	if err := os.WriteFile(settingsPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []string{".gemini/settings.json"}
	before := HashSentinelFiles(projectRoot, files)
	if before[".gemini/settings.json"] == "" {
		t.Fatal("expected non-empty hash for present settings file")
	}

	// Simulate the agent rewriting the file with an OAuth refresh —
	// hooks subtree unchanged, only metadata fields differ.
	refreshed := `{
  "hooks": {
    "BeforeTool": [
      {
        "hooks": [
          {"command": "/bin/sir guard evaluate", "type": "command"}
        ]
      }
    ]
  },
  "selectedAuthType": "oauth-personal",
  "oauth_refreshed_at": "2026-04-14T12:34:56Z",
  "session_telemetry": {"runs": 17}
}`
	if err := os.WriteFile(settingsPath, []byte(refreshed), 0o600); err != nil {
		t.Fatal(err)
	}
	after := HashSentinelFiles(projectRoot, files)
	if after[".gemini/settings.json"] != before[".gemini/settings.json"] {
		t.Fatalf("agent metadata refresh should not change hooks-subtree hash; before=%s after=%s",
			before[".gemini/settings.json"], after[".gemini/settings.json"])
	}

	// Now mutate the hooks subtree itself — hash MUST change so the
	// security-relevant tamper detection still fires.
	tampered := `{
  "hooks": {
    "BeforeTool": [
      {
        "hooks": [
          {"command": "/tmp/evil/sir guard evaluate", "type": "command"}
        ]
      }
    ]
  },
  "selectedAuthType": "oauth-personal"
}`
	if err := os.WriteFile(settingsPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	tamperedHashes := HashSentinelFiles(projectRoot, files)
	if tamperedHashes[".gemini/settings.json"] == before[".gemini/settings.json"] {
		t.Fatal("hooks-subtree mutation should change the hash; tamper detection broken")
	}
}

// TestHashSentinelFiles_NonAgentFilesHashWholeFile confirms that posture
// files NOT registered as a host agent's hook config (CLAUDE.md, .env)
// continue to use whole-file hashing — those have no managed subtree to
// narrow to and any change is security-relevant.
func TestHashSentinelFiles_NonAgentFilesHashWholeFile(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)
	projectRoot := t.TempDir()

	postureFile := filepath.Join(projectRoot, "CLAUDE.md")
	if err := os.WriteFile(postureFile, []byte("# rules"), 0o600); err != nil {
		t.Fatal(err)
	}

	files := []string{"CLAUDE.md"}
	before := HashSentinelFiles(projectRoot, files)
	if before["CLAUDE.md"] == "" {
		t.Fatal("expected non-empty hash for present file")
	}

	if err := os.WriteFile(postureFile, []byte("# rules edited"), 0o600); err != nil {
		t.Fatal(err)
	}
	after := HashSentinelFiles(projectRoot, files)
	if after["CLAUDE.md"] == before["CLAUDE.md"] {
		t.Fatal("non-agent posture file change should change whole-file hash")
	}
}
