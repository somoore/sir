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
	if p := macAppHelperPath(command); p != "" {
		return true, p
	}
	if isShellWrapper(command) && len(args) == 2 && args[0] == "-c" {
		inner := unquoteShellPayload(args[1])
		if p := macAppHelperPath(inner); p != "" {
			return true, p
		}
	}
	return false, ""
}

func macAppHelperPath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/Applications/") {
		return ""
	}
	// Require both a .app/Contents/ prefix AND a MacOS/ or XPCServices/ segment.
	// Matching bare /Applications/ would pull in installer payloads and
	// non-bundle binaries we have no reason to exempt from sandboxing.
	if !strings.Contains(p, ".app/Contents/") {
		return ""
	}
	if strings.Contains(p, "/Contents/MacOS/") || strings.Contains(p, "/Contents/XPCServices/") {
		return p
	}
	return ""
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
			return s[1 : len(s)-1]
		}
	}
	return s
}
