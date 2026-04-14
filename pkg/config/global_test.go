package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withHome redirects HOME to a temp dir for the duration of the test.
func withHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestLoad_MissingReturnsDefaults(t *testing.T) {
	withHome(t)
	c, ok, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for missing file")
	}
	if c.MCPTrustPosture != PostureStandard {
		t.Fatalf("default posture = %q, want %q", c.MCPTrustPosture, PostureStandard)
	}
}

func TestLoad_FailClosedOnCorrupt(t *testing.T) {
	home := withHome(t)
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{not valid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load()
	if err == nil {
		t.Fatal("expected error on corrupt config, got nil")
	}
}

// TestLoad_RejectsUnknownPosture pins the codex P1 fix: an invalid
// posture value (typo, corruption) must NOT silently fall through the
// install switch's default branch and widen MCP trust. Load fails
// closed and the install path will refuse to proceed.
func TestLoad_RejectsUnknownPosture(t *testing.T) {
	home := withHome(t)
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"mcp_trust_posture":"strcit"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load()
	if err == nil {
		t.Fatal("expected error on unknown posture value, got nil")
	}
	if !strings.Contains(err.Error(), "strcit") {
		t.Errorf("error should mention the offending value, got %q", err.Error())
	}
}

func TestLoad_EmptyPostureDefaultsStandard(t *testing.T) {
	home := withHome(t)
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// Empty JSON object — valid, but posture unset.
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, ok, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true for present file")
	}
	if c.MCPTrustPosture != PostureStandard {
		t.Fatalf("posture = %q, want %q", c.MCPTrustPosture, PostureStandard)
	}
}

func TestSaveAndLoad_Roundtrip(t *testing.T) {
	withHome(t)
	c := &Config{MCPTrustPosture: PostureStrict}
	if err := c.Save(); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, ok, err := Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !ok {
		t.Fatal("expected ok=true after save")
	}
	if loaded.MCPTrustPosture != PostureStrict {
		t.Fatalf("posture = %q, want %q", loaded.MCPTrustPosture, PostureStrict)
	}
	if loaded.UpdatedAt.IsZero() {
		t.Fatal("expected UpdatedAt to be set by Save")
	}
}

func TestIsFirstInstall(t *testing.T) {
	home := withHome(t)
	first, err := IsFirstInstall()
	if err != nil {
		t.Fatal(err)
	}
	if !first {
		t.Fatal("expected first install when manifest absent")
	}
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "binary-manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err = IsFirstInstall()
	if err != nil {
		t.Fatal(err)
	}
	if first {
		t.Fatal("expected not-first-install after manifest write")
	}
}

func TestIsValidPosture(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"strict", true},
		{"standard", true},
		{"permissive", true},
		{"", false},
		{"loose", false},
		{"STRICT", false}, // case-sensitive by design
	}
	for _, tc := range cases {
		if got := IsValidPosture(tc.in); got != tc.want {
			t.Errorf("IsValidPosture(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
