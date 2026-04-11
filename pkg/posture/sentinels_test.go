package posture

import (
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
