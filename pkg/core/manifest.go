package core

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// BinaryManifest records the SHA-256 hashes of sir and mister-core at install
// time. Both install.sh (source build) and download.sh (pre-built) write this
// file to ~/.sir/binary-manifest.json after installing binaries.
type BinaryManifest struct {
	Version          string `json:"version"`
	InstalledAt      string `json:"installed_at"`
	InstallMethod    string `json:"install_method"`
	SirSHA256        string `json:"sir_sha256"`
	MisterCoreSHA256 string `json:"mister_core_sha256"`
	SirPath          string `json:"sir_path"`
	MisterCorePath   string `json:"mister_core_path"`
}

// ManifestPath returns the path to the binary manifest file.
func ManifestPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".sir", "binary-manifest.json"), nil
}

// ManifestSentinelPath returns the path to the sentinel file that records
// whether a manifest has ever been written. When the sentinel exists but
// the manifest does not, the manifest was deleted — treat as tamper.
func ManifestSentinelPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".sir", ".manifest-expected"), nil
}

// LoadManifest reads and parses the binary manifest from ~/.sir/binary-manifest.json.
// Returns (nil, nil) if neither the manifest nor the sentinel exist (pre-upgrade installs).
// Returns an error if the sentinel exists but the manifest does not (tamper).
func LoadManifest() (*BinaryManifest, error) {
	path, err := ManifestPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, checkManifestSentinel()
		}
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m BinaryManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// checkManifestSentinel distinguishes "never had a manifest" (pre-upgrade)
// from "manifest was deleted" (tamper). Returns nil if no sentinel exists,
// or an error if the sentinel is present without a manifest.
func checkManifestSentinel() error {
	sentinelPath, err := ManifestSentinelPath()
	if err != nil {
		return nil // can't resolve path → treat as pre-upgrade
	}
	if _, err := os.Stat(sentinelPath); err == nil {
		return fmt.Errorf("binary manifest deleted — sentinel exists at %s but manifest is missing (possible tamper)", sentinelPath)
	}
	return nil // no sentinel → pre-upgrade install, skip check
}

// HashFile returns the lowercase hex SHA-256 digest of a file.
func HashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h), nil
}
