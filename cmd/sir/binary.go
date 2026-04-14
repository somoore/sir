package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// sirBinaryPath is the resolved absolute path to the sir binary.
// Set once at startup by resolveSirBinary(). Tests override this to a
// fixed value so hook commands are predictable regardless of test-binary path.
var sirBinaryPath string

func init() {
	sirBinaryPath = resolveSirBinaryPath()
}

// resolveSirBinaryPath returns the absolute path to the sir binary.
// This is critical for security: hook commands must use an absolute path
// to prevent $PATH hijacking (an agent could place a malicious "sir" binary
// in a writable PATH directory and intercept all hook invocations).
// Falls back to exec.LookPath if os.Executable fails. Returns "sir" as last resort.
func resolveSirBinaryPath() string {
	if exePath, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
			return resolved
		}
		return exePath
	}
	if lookPath, err := exec.LookPath("sir"); err == nil {
		if resolved, err := filepath.Abs(lookPath); err == nil {
			return resolved
		}
		return lookPath
	}
	return "sir"
}

// isSirHookCommand returns true if cmd is a sir hook command.
//
// Two-layer match:
//
//  1. Anything written by THIS process's binary path always counts (the
//     original `sirBinaryPath + " guard "` substring check). This keeps
//     test binaries and any future non-`sir` basenames recognized when
//     they invoke themselves.
//  2. Otherwise, structural match: any command of shape
//     "<...>/sir guard <subcommand> [args]" is treated as a sir hook,
//     regardless of the absolute path. This is required so re-running
//     `sir install` from a different binary path (symlink swap,
//     brew→source migration, dev build) recognizes previously-installed
//     entries and replaces them rather than appending.
//
// Matching by sirBinaryPath alone — the original implementation —
// caused hook duplication: install would write its own path entry
// without recognizing the existing entry as belonging to sir, so both
// stayed in the settings file and both fired on every tool call. The
// structural fallback closes that hole.
//
// The structural check accepts basename `sir` or `sir.exe`. A non-sir
// binary literally named `sir` invoked with a `guard` subcommand would
// match; that's a vanishingly small false-positive surface relative to
// the false-negative the path-pinned version produced.
func isSirHookCommand(cmd string) bool {
	if sirBinaryPath != "" && strings.Contains(cmd, sirBinaryPath+" guard ") {
		return true
	}
	fields := strings.Fields(cmd)
	if len(fields) < 2 {
		return false
	}
	base := strings.ToLower(filepath.Base(fields[0]))
	if base != "sir" && base != "sir.exe" {
		return false
	}
	return fields[1] == "guard"
}
