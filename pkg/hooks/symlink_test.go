package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// resolveSymlink resolves a path through symlinks. If the path is a symlink,
// it returns the resolved target. If resolution fails or the symlink is broken,
// it returns the original path and an error.
func resolveSymlink(root, path string) (string, error) {
	fullPath := filepath.Join(root, path)
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return path, err
	}
	// Also resolve the root to handle /var -> /private/var on macOS
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return resolved, nil
	}
	// Make relative to resolved root
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil {
		return resolved, nil
	}
	return rel, nil
}

func TestSymlinkToEnvDetectedAsSensitive(t *testing.T) {
	tmpDir := t.TempDir()
	l := lease.DefaultLease()

	// Create actual .env file
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=value"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create symlink: harmless-config -> .env
	linkPath := filepath.Join(tmpDir, "harmless-config")
	if err := os.Symlink(envPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	// Resolve the symlink and check if the resolved path is sensitive
	resolved, err := resolveSymlink(tmpDir, "harmless-config")
	if err != nil {
		t.Fatalf("failed to resolve symlink: %v", err)
	}

	if !IsSensitivePath(resolved, l) {
		t.Errorf("symlink to .env should be detected as sensitive after resolution, resolved to %q", resolved)
	}
}

func TestSymlinkToPostureFileDetectedAsPosture(t *testing.T) {
	tmpDir := t.TempDir()
	l := lease.DefaultLease()

	// Create posture file
	settingsDir := filepath.Join(tmpDir, ".claude")
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(settingsDir, "settings.json")
	if err := os.WriteFile(settingsPath, []byte(`{"hooks": {}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create symlink: config-link -> .claude/settings.json
	linkPath := filepath.Join(tmpDir, "config-link")
	if err := os.Symlink(settingsPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	resolved, err := resolveSymlink(tmpDir, "config-link")
	if err != nil {
		t.Fatalf("failed to resolve symlink: %v", err)
	}

	if !IsPostureFile(resolved, l) {
		t.Errorf("symlink to settings.json should be detected as posture after resolution, resolved to %q", resolved)
	}
}

func TestBrokenSymlinkGracefulHandling(t *testing.T) {
	tmpDir := t.TempDir()

	// Create symlink to non-existent target
	linkPath := filepath.Join(tmpDir, "broken-link")
	if err := os.Symlink(filepath.Join(tmpDir, "nonexistent-file"), linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	// resolveSymlink should return an error but not panic
	_, err := resolveSymlink(tmpDir, "broken-link")
	if err == nil {
		t.Error("expected error for broken symlink")
	}
}

func TestSymlinkOutsideProjectRoot(t *testing.T) {
	tmpDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create a file outside the project root
	outsideFile := filepath.Join(outsideDir, "outside-secret.env")
	if err := os.WriteFile(outsideFile, []byte("OUTSIDE_SECRET=value"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create symlink pointing outside the project root
	linkPath := filepath.Join(tmpDir, "external-link")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	// Resolve should succeed but the resolved path will be outside root
	resolved, err := resolveSymlink(tmpDir, "external-link")
	if err != nil {
		// Rel() might fail if paths are on different volume roots,
		// in which case we get the absolute path back.
		// Either way, no panic is the requirement.
		t.Logf("resolveSymlink returned error (acceptable): %v", err)
		return
	}

	// The resolved path should either be absolute (outside root) or
	// start with ".." indicating it's outside the project.
	// This is a safety check: the caller should validate the resolved path
	// is within the project boundary.
	if filepath.IsAbs(resolved) {
		t.Logf("resolved to absolute path outside project: %s (caller must validate)", resolved)
	} else if len(resolved) >= 2 && resolved[:2] == ".." {
		t.Logf("resolved to relative path outside project: %s (caller must validate)", resolved)
	}
	// No assertion failure - the goal is graceful handling, not crash.
}

func TestSymlinkChainResolution(t *testing.T) {
	tmpDir := t.TempDir()
	l := lease.DefaultLease()

	// Create .env
	envPath := filepath.Join(tmpDir, ".env")
	if err := os.WriteFile(envPath, []byte("KEY=val"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create chain: link2 -> link1 -> .env
	link1 := filepath.Join(tmpDir, "link1")
	if err := os.Symlink(envPath, link1); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	link2 := filepath.Join(tmpDir, "link2")
	if err := os.Symlink(link1, link2); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	resolved, err := resolveSymlink(tmpDir, "link2")
	if err != nil {
		t.Fatalf("failed to resolve symlink chain: %v", err)
	}

	if !IsSensitivePath(resolved, l) {
		t.Errorf("double-symlink to .env should resolve to sensitive path, got %q", resolved)
	}
}

func TestNonSymlinkPathResolution(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a regular file
	filePath := filepath.Join(tmpDir, "regular.txt")
	if err := os.WriteFile(filePath, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	// resolveSymlink on a regular file should return the same path
	resolved, err := resolveSymlink(tmpDir, "regular.txt")
	if err != nil {
		t.Fatalf("unexpected error for regular file: %v", err)
	}

	if resolved != "regular.txt" {
		t.Errorf("expected regular.txt, got %q", resolved)
	}
}

func TestSymlinkToSensitiveKeyFile(t *testing.T) {
	tmpDir := t.TempDir()
	l := lease.DefaultLease()

	// Create a .key file
	keyPath := filepath.Join(tmpDir, "server.key")
	if err := os.WriteFile(keyPath, []byte("PRIVATE KEY DATA"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Symlink with innocent name
	linkPath := filepath.Join(tmpDir, "config.txt")
	if err := os.Symlink(keyPath, linkPath); err != nil {
		t.Skipf("symlinks not supported: %v", err)
	}

	resolved, err := resolveSymlink(tmpDir, "config.txt")
	if err != nil {
		t.Fatal(err)
	}

	if !IsSensitivePath(resolved, l) {
		t.Errorf("symlink to server.key should be detected as sensitive, resolved to %q", resolved)
	}
}
