package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// HashCommand returns the sha256 hex digest of the binary at the given path.
//
// If path is empty, returns ("", nil). MCP servers launched via npx/uvx or
// via $PATH often do not have a stable command path at discovery time, and
// we record an empty hash rather than failing approval. The trade-off: such
// servers get no binary-tamper detection, which is honest — the binary
// identity is not pinned by the config. Document this in the approval UI.
//
// Launcher commands (npx, uvx, pipx, bunx, pnpm, npm, yarn, deno, uv) are
// also skipped: their on-disk bytes change whenever the user upgrades
// Node / Python / Bun (e.g., `nvm use 20`), but the MCP code they launch
// lives elsewhere (package registry, args). Pinning the launcher would
// produce noisy drift on routine toolchain upgrades without catching any
// real substitution of the MCP server itself. Users who configure a
// real local binary still get real pinning.
//
// If path is non-empty but relative (bare command like "uvx"), we resolve
// via PATH. If that still yields nothing readable, returns ("", nil) — same
// rationale. Only unambiguous filesystem errors on an absolute or resolved
// path surface as errors.
func HashCommand(path string) (string, error) {
	if path == "" || isLauncherCommand(path) {
		return "", nil
	}
	resolved, ok := resolveCommandPath(path)
	if !ok {
		return "", nil
	}
	f, err := os.Open(resolved) // #nosec G304 -- path is either caller-provided or exec.LookPath resolved
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// StatCommand returns the mtime and sha256 of the binary at the given
// path in one pass, stat'ing the resolved path. Returns (zero, "", nil)
// when the path is empty or cannot be resolved via PATH, matching the
// same "honest empty" semantics as HashCommand.
//
// Intended for the binary-drift gate, which uses mtime as a cheap
// fast-path before rehashing. mtime is advisory only — hash remains the
// source of truth — so tests that manipulate mtime without content
// changes must account for this.
func StatCommand(path string) (time.Time, string, error) {
	if path == "" || isLauncherCommand(path) {
		return time.Time{}, "", nil
	}
	resolved, ok := resolveCommandPath(path)
	if !ok {
		return time.Time{}, "", nil
	}
	fi, err := os.Stat(resolved) // #nosec G304
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, "", nil
		}
		return time.Time{}, "", err
	}
	hash, err := HashCommand(resolved)
	if err != nil {
		return time.Time{}, "", err
	}
	return fi.ModTime(), hash, nil
}

// launcherBasenames are commands whose on-disk bytes are unrelated to
// the MCP code they launch. Pinning them produces false drift on
// routine toolchain upgrades (nvm use, brew upgrade, pyenv install).
// Keep narrow: only add basenames whose package-launcher role is
// unambiguous. Generic interpreters like `node` / `python` are NOT on
// this list because they might point at a bespoke entrypoint whose
// content IS worth pinning.
var launcherBasenames = map[string]struct{}{
	"npx":  {},
	"uvx":  {},
	"pipx": {},
	"bunx": {},
	"pnpm": {},
	"npm":  {},
	"yarn": {},
	"deno": {},
	"uv":   {},
}

// isLauncherCommand reports whether the given path's basename identifies
// a package launcher whose bytes should not be pinned. Checked against
// the raw input so a bare "npx" and an absolute "/usr/local/bin/npx"
// both match.
func isLauncherCommand(path string) bool {
	base := filepath.Base(path)
	_, ok := launcherBasenames[base]
	return ok
}

// resolveCommandPath returns (path, true) if path is absolute and valid,
// or (resolved, true) if it can be located via PATH. Returns ("", false)
// for empty, relative-but-unresolvable, or cannot-stat cases. Matches
// the existing HashCommand resolution rules so StatCommand and
// HashCommand stay consistent.
func resolveCommandPath(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	if filepath.IsAbs(path) {
		return path, true
	}
	resolved, err := exec.LookPath(path)
	if err != nil {
		return "", false
	}
	return resolved, true
}
