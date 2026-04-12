package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHashFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test-binary")
	if err := os.WriteFile(path, []byte("hello mister-core"), 0o644); err != nil {
		t.Fatal(err)
	}

	hash, err := HashFile(path)
	if err != nil {
		t.Fatalf("HashFile: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("expected 64-char hex hash, got %d chars: %s", len(hash), hash)
	}

	// Same content must produce the same hash.
	hash2, _ := HashFile(path)
	if hash != hash2 {
		t.Fatalf("determinism broken: %s != %s", hash, hash2)
	}
}

func TestHashFile_NotFound(t *testing.T) {
	_, err := HashFile("/nonexistent/binary")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadManifest_NotFound(t *testing.T) {
	// Point HOME at a temp dir so no real manifest interferes.
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	m, err := LoadManifest()
	if err != nil {
		t.Fatalf("expected nil error for missing manifest, got: %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil manifest, got: %+v", m)
	}
}

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	manifest := BinaryManifest{
		Version:          "v0.0.3",
		InstalledAt:      "2026-04-12T17:00:00Z",
		InstallMethod:    "source",
		SirSHA256:        "aaa111",
		MisterCoreSHA256: "bbb222",
		SirPath:          "/home/test/.local/bin/sir",
		MisterCorePath:   "/home/test/.local/bin/mister-core",
	}

	sirDir := filepath.Join(dir, ".sir")
	if err := os.MkdirAll(sirDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(manifest)
	if err := os.WriteFile(filepath.Join(sirDir, "binary-manifest.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadManifest()
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil manifest")
	}
	if loaded.Version != "v0.0.3" {
		t.Errorf("version = %q, want v0.0.3", loaded.Version)
	}
	if loaded.MisterCoreSHA256 != "bbb222" {
		t.Errorf("mister_core_sha256 = %q, want bbb222", loaded.MisterCoreSHA256)
	}
}

func TestLoadManifest_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	sirDir := filepath.Join(dir, ".sir")
	os.MkdirAll(sirDir, 0o700)
	os.WriteFile(filepath.Join(sirDir, "binary-manifest.json"), []byte("{bad json"), 0o600)

	_, err := LoadManifest()
	if err == nil {
		t.Fatal("expected error for malformed manifest")
	}
}

func TestVerifyMisterCoreOnce_NoManifest(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ResetIntegrityCache()

	// No manifest → should pass (nil error).
	err := verifyMisterCoreOnce("/some/binary")
	if err != nil {
		t.Fatalf("expected nil error with no manifest, got: %v", err)
	}
}

func TestVerifyMisterCoreOnce_HashMatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ResetIntegrityCache()

	// Create a fake binary.
	binaryPath := filepath.Join(dir, "mister-core")
	os.WriteFile(binaryPath, []byte("fake-mister-core-binary"), 0o755)

	// Compute its real hash and write a matching manifest.
	realHash, _ := HashFile(binaryPath)
	writeTestManifest(t, dir, realHash)

	err := verifyMisterCoreOnce(binaryPath)
	if err != nil {
		t.Fatalf("expected nil error for matching hash, got: %v", err)
	}
}

func TestVerifyMisterCoreOnce_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ResetIntegrityCache()

	// Create a fake binary.
	binaryPath := filepath.Join(dir, "mister-core")
	os.WriteFile(binaryPath, []byte("fake-mister-core-binary"), 0o755)

	// Write a manifest with a WRONG hash.
	writeTestManifest(t, dir, "0000000000000000000000000000000000000000000000000000000000000000")

	err := verifyMisterCoreOnce(binaryPath)
	if err == nil {
		t.Fatal("expected error for mismatched hash")
	}
}

func TestVerifyMisterCoreOnce_ShortManifestHash(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ResetIntegrityCache()

	binaryPath := filepath.Join(dir, "mister-core")
	os.WriteFile(binaryPath, []byte("fake-mister-core-binary"), 0o755)

	// Write a manifest with a malformed short hash — must not panic.
	writeTestManifest(t, dir, "abc")

	err := verifyMisterCoreOnce(binaryPath)
	if err == nil {
		t.Fatal("expected error for mismatched short hash")
	}
}

func TestVerifyMisterCoreOnce_CachedResult(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	ResetIntegrityCache()

	binaryPath := filepath.Join(dir, "mister-core")
	os.WriteFile(binaryPath, []byte("original"), 0o755)
	realHash, _ := HashFile(binaryPath)
	writeTestManifest(t, dir, realHash)

	// First call — passes.
	if err := verifyMisterCoreOnce(binaryPath); err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Tamper with the binary AFTER the first check.
	os.WriteFile(binaryPath, []byte("tampered"), 0o755)

	// Second call still passes because the result is cached per-process.
	if err := verifyMisterCoreOnce(binaryPath); err != nil {
		t.Fatalf("cached call should still pass: %v", err)
	}

	// But a fresh cache catches the tamper.
	ResetIntegrityCache()
	if err := verifyMisterCoreOnce(binaryPath); err == nil {
		t.Fatal("expected error after cache reset with tampered binary")
	}
}

func writeTestManifest(t *testing.T, homeDir, mcHash string) {
	t.Helper()
	sirDir := filepath.Join(homeDir, ".sir")
	os.MkdirAll(sirDir, 0o700)
	m := BinaryManifest{
		Version:          "v0.0.3",
		MisterCoreSHA256: mcHash,
	}
	data, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(sirDir, "binary-manifest.json"), data, 0o600)
}
