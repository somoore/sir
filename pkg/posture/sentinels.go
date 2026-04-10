package posture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
)

// ResolvePath returns the actual filesystem path for a posture/sentinel file.
// Most files are relative to the project root, but certain agent posture files
// are machine-wide (global) rather than per-project.
func ResolvePath(root, relPath string) string {
	switch relPath {
	case ".claude/settings.json":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".claude", "settings.json")
		}
	case ".codex/config.toml":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".codex", "config.toml")
		}
	case ".codex/hooks.json":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".codex", "hooks.json")
		}
	}
	return filepath.Join(root, relPath)
}

// HashSentinelFiles computes SHA-256 hashes of sentinel files.
// Files that don't exist are recorded with an empty hash.
func HashSentinelFiles(root string, files []string) map[string]string {
	hashes := make(map[string]string, len(files))
	for _, f := range files {
		fullPath := ResolvePath(root, f)
		resolved, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			hashes[f] = ""
			continue
		}
		data, err := os.ReadFile(resolved)
		if err != nil {
			hashes[f] = ""
			continue
		}
		h := sha256.Sum256(data)
		hashes[f] = fmt.Sprintf("%x", h)
	}
	return hashes
}

// CompareSentinelHashes compares before and after sentinel hashes and returns
// a list of files that changed.
func CompareSentinelHashes(before, after map[string]string) []string {
	var changed []string
	for file, beforeHash := range before {
		afterHash, ok := after[file]
		if !ok {
			if beforeHash != "" {
				changed = append(changed, file)
			}
			continue
		}
		if beforeHash != afterHash {
			changed = append(changed, file)
		}
	}
	for file := range after {
		if _, ok := before[file]; !ok && after[file] != "" {
			changed = append(changed, file)
		}
	}
	return changed
}
