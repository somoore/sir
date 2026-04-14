package mcp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHashCommand_Empty(t *testing.T) {
	got, err := HashCommand("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty hash, got %q", got)
	}
}

func TestHashCommand_FileContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("hello"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	got, err := HashCommand(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// sha256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("hash = %q, want %q", got, want)
	}
}

func TestHashCommand_Missing(t *testing.T) {
	// Absolute missing path → ("", nil). Philosophically consistent with
	// "bare command not in PATH" — we record empty hash and let approval
	// proceed; binary-tamper detection is best-effort.
	got, err := HashCommand("/nonexistent/path/that/should/not/be/there")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty hash for missing file, got %q", got)
	}
}

func TestHashCommand_BareCommandNotInPath(t *testing.T) {
	got, err := HashCommand("this-command-definitely-does-not-exist-zzz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected empty hash for unresolvable command, got %q", got)
	}
}

func TestHashCommand_LauncherSkipped(t *testing.T) {
	// Launcher commands (npx, uvx, etc.) should never be hashed — their
	// bytes change on toolchain upgrades without meaning. Covers both
	// bare names and absolute paths.
	cases := []string{
		"npx",
		"uvx",
		"/usr/local/bin/npx",
		"/opt/homebrew/bin/pnpm",
	}
	for _, c := range cases {
		got, err := HashCommand(c)
		if err != nil {
			t.Fatalf("HashCommand(%q): unexpected error: %v", c, err)
		}
		if got != "" {
			t.Errorf("HashCommand(%q) = %q, want empty (launcher skip)", c, got)
		}
	}
}

func TestStatCommand_LauncherSkipped(t *testing.T) {
	mtime, hash, err := StatCommand("npx")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !mtime.IsZero() || hash != "" {
		t.Fatalf("StatCommand(\"npx\") = (%v, %q), want zero/empty", mtime, hash)
	}
}

func TestIsLauncherCommand(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"npx", true},
		{"uvx", true},
		{"/usr/local/bin/npx", true},
		{"node", false},   // NOT a launcher — bespoke entrypoint may be passed as arg
		{"python", false}, // same rationale
		{"/usr/local/bin/mcp-server", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLauncherCommand(tc.in); got != tc.want {
			t.Errorf("isLauncherCommand(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestHashCommand_DeterministicAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bin")
	if err := os.WriteFile(p, []byte("deterministic"), 0o755); err != nil { //nolint:gosec
		t.Fatal(err)
	}
	a, err := HashCommand(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HashCommand(p)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("hash not stable: %q vs %q", a, b)
	}
}
