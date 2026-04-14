package mcp

import (
	"path/filepath"
	"strings"
)

// IsMacAppHelperCommand reports whether the given command (optionally via a
// shell wrapper) resolves to a macOS app helper binary under
// /Applications/*.app/Contents/MacOS/ or /Applications/*.app/Contents/XPCServices/.
//
// These binaries typically XPC to their parent .app and fail silently under
// sandbox-exec on macOS: the mach-lookup to the app's registered service is
// blocked (or the helper self-checks and refuses). Hopper Disassembler's
// HopperMCPServer is the reference case — it returns zero bytes under any
// sandbox-exec profile, even one that allows everything, because the XPC
// handshake to Hopper.app can't complete.
//
// Security model: matching this pattern is what causes sir to DROP its
// sandbox-exec wrapper, so the check must not be bypassable by an attacker
// who controls the MCP config. The implementation defends against two
// classes of attack:
//
//  1. Path traversal: /Applications/Foo.app/Contents/MacOS/../../../../bin/sh
//     would match a naive substring check but actually launches /bin/sh.
//     filepath.Clean normalizes the string before the shape check, so the
//     traversal collapses to /bin/sh and the shape check rejects it.
//  2. Symlink substitution: a symlink named
//     /Applications/Foo.app/Contents/MacOS/evil pointing at /bin/sh would
//     match the shape but launch /bin/sh. filepath.EvalSymlinks resolves
//     the final target and re-classifies it; if the target leaves the
//     bundle subtree, auto-degrade is refused. An attacker who can write
//     inside /Applications/*.app/ is already privileged — this is defense
//     in depth, not the sole barrier.
//
// If the path does not exist on disk at all (EvalSymlinks errors) we fail
// closed: auto-degrade requires a verifiable target. Real invocations
// always have the binary present; a non-existent path would fail to launch
// anyway. Unit tests exercise the pure shape classifier
// (classifyAppHelperShape) to cover traversal and negative cases without
// needing writes into /Applications.
//
// The detection handles two invocation shapes produced by real .mcp.json
// configurations:
//
//  1. Direct: command="/Applications/X.app/Contents/MacOS/Y", args=[...]
//  2. Shell wrapper: command="/bin/bash", args=["-c", "'/Applications/.../Y'"]
//     (Claude Code generates this shape when the path has a space.) Both
//     single-quoted and double-quoted payloads are unquoted before matching.
//
// Returns (true, resolvedPath) on a match; the caller uses the path for the
// degradation notice it emits to stderr.
func IsMacAppHelperCommand(command string, args []string) (bool, string) {
	if ok, p := resolveAppHelperPath(command); ok {
		return true, p
	}
	if isShellWrapper(command) && len(args) == 2 && args[0] == "-c" {
		inner := unquoteShellPayload(args[1])
		if ok, p := resolveAppHelperPath(inner); ok {
			return true, p
		}
	}
	return false, ""
}

// resolveAppHelperPath canonicalizes p via Clean + EvalSymlinks and
// returns (true, canonical) iff BOTH the cleaned input AND the resolved
// target are shaped like an .app helper. File-not-found is treated as a
// non-match (fail closed).
func resolveAppHelperPath(p string) (bool, string) {
	p = strings.TrimSpace(p)
	if p == "" {
		return false, ""
	}
	// Clean first so a traversal becomes the real path before any shape
	// check. After Clean, /Applications/Foo.app/Contents/MacOS/../../bin/sh
	// collapses to /bin/sh and the shape check rejects it outright.
	cleaned := filepath.Clean(p)
	if !classifyAppHelperShape(cleaned) {
		return false, ""
	}
	// Resolve symlinks and verify the resolved target still lives inside
	// the bundle. EvalSymlinks requires the file to exist; refusing to
	// match a missing file is acceptable because launching it would fail
	// anyway.
	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return false, ""
	}
	if !classifyAppHelperShape(resolved) {
		return false, ""
	}
	return true, resolved
}

// classifyAppHelperShape is the pure string classifier: an absolute, cleaned
// path under /Applications/<name>.app/Contents/{MacOS,XPCServices}/. Rejects
// anything whose cleaned form differs from the input, because a differing
// form means the input contained redundant separators or traversal segments
// that could shift meaning.
func classifyAppHelperShape(p string) bool {
	if p == "" {
		return false
	}
	if filepath.Clean(p) != p {
		return false
	}
	if !strings.HasPrefix(p, "/Applications/") {
		return false
	}
	if !strings.Contains(p, ".app/Contents/") {
		return false
	}
	return strings.Contains(p, "/Contents/MacOS/") ||
		strings.Contains(p, "/Contents/XPCServices/")
}

func isShellWrapper(cmd string) bool {
	base := filepath.Base(strings.TrimSpace(cmd))
	switch base {
	case "bash", "sh", "zsh", "dash":
		return true
	}
	return false
}

// unquoteShellPayload strips a single layer of matching single or double
// quotes around a shell -c payload. We intentionally do not try to parse
// arbitrary shell — the real-world cases this fixes are simple single-path
// invocations; anything more complex stays sandboxed (safer default).
func unquoteShellPayload(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			return strings.TrimSpace(s[1 : len(s)-1])
		}
	}
	return s
}
