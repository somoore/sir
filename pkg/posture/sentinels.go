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
	case ".gemini/settings.json":
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, ".gemini", "settings.json")
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
//
// For files registered as a host agent's hook config (claude / gemini /
// codex settings.json), the hash covers only the managed hook subtree.
// This prevents the agent's own session-time writes (OAuth refresh,
// session telemetry, account metadata) from tripping posture-tamper
// detection. Security-relevant changes (hook commands, paths) still
// land in the subtree and still produce a hash mismatch.
//
// For non-agent posture files (CLAUDE.md, .env, etc.) the whole file
// is hashed — those have no "subtree" to narrow to.
func HashSentinelFiles(root string, files []string) map[string]string {
	hashes := make(map[string]string, len(files))
	for _, f := range files {
		hashes[f] = hashSentinelFile(root, f)
	}
	return hashes
}

func hashSentinelFile(root, relPath string) string {
	fullPath := ResolvePath(root, relPath)
	resolved, err := filepath.EvalSymlinks(fullPath)
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return ""
	}
	if hookFile, ok := LookupAgentHookFileByRelativePath(relPath); ok {
		if subtree, subErr := ExtractManagedSubtree(data, hookFile.managedSubtreeKey()); subErr == nil {
			h := sha256.Sum256(subtree)
			return fmt.Sprintf("%x", h)
		}
		// Fall through to full-file hash if subtree extraction fails
		// (malformed JSON, etc.) — hash mismatch is the safer default.
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h)
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
