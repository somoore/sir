package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

// TestRunMCPProxyDarwin_AutoDegradesMacAppHelper checks that a command
// matching the Mac-app-helper heuristic skips sandbox-exec entirely and
// falls through to monitored mode. The helper classifier now requires the
// target path to exist (so we can resolve symlinks before classification);
// synthetic paths no longer match. Use a real /Applications helper if one
// is present on this machine; otherwise skip — the CI matrix covers the
// classifier's unit tests directly.
func TestRunMCPProxyDarwin_AutoDegradesMacAppHelper(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-only code path")
	}
	realHelper := findRealAppHelper(t)
	if realHelper == "" {
		t.Skip("no /Applications/*.app/Contents/MacOS/* helper available on this host")
	}
	opts := mcpProxyOpts{command: realHelper}

	stderr := &bytes.Buffer{}
	restore := redirectStderr(t, stderr)
	defer restore()

	_ = runMCPProxyDarwin(opts)

	restore()
	if !strings.Contains(stderr.String(), "monitored mode") {
		t.Errorf("expected auto-degrade notice in stderr; got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "macOS .app helper") {
		t.Errorf("expected Mac-app-helper reason in notice; got:\n%s", stderr.String())
	}
}

// findRealAppHelper walks /Applications looking for a regular-file helper
// under any .app bundle we can use in the auto-degrade integration test.
// Returns "" if none found (uncommon but possible in sparse CI images).
func findRealAppHelper(t *testing.T) string {
	t.Helper()
	entries, err := os.ReadDir("/Applications")
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() || filepath.Ext(e.Name()) != ".app" {
			continue
		}
		macosDir := filepath.Join("/Applications", e.Name(), "Contents", "MacOS")
		helpers, err := os.ReadDir(macosDir)
		if err != nil {
			continue
		}
		for _, h := range helpers {
			if h.IsDir() {
				continue
			}
			return filepath.Join(macosDir, h.Name())
		}
	}
	return ""
}

// TestRunMCPProxyDarwin_NoSandboxFlagDegrades verifies the explicit opt-out
// path produces its own distinct notice so auditors can distinguish
// user-initiated degradation from the auto-detector.
func TestRunMCPProxyDarwin_NoSandboxFlagDegrades(t *testing.T) {
	opts := mcpProxyOpts{
		command:   "/usr/bin/true",
		noSandbox: true,
	}

	stderr := &bytes.Buffer{}
	restore := redirectStderr(t, stderr)
	defer restore()

	code := runMCPProxyDarwin(opts)
	restore()

	if code != 0 {
		t.Errorf("runMCPProxyDarwin(--no-sandbox, /usr/bin/true) exit = %d, want 0", code)
	}
	if !strings.Contains(stderr.String(), "--no-sandbox requested") {
		t.Errorf("expected --no-sandbox notice in stderr; got:\n%s", stderr.String())
	}
}

// TestRunMCPProxyDarwin_NonHelperStillSandboxed is the anti-regression:
// a plain node/python invocation must NOT take the degrade path. We can't
// easily assert sandbox-exec actually fired in a unit test (it's macOS-
// native and requires entitlements), so we negate: stderr must contain
// neither degrade-notice shape.
func TestRunMCPProxyDarwin_NonHelperStillSandboxed(t *testing.T) {
	opts := mcpProxyOpts{
		command: "/usr/bin/true",
	}

	stderr := &bytes.Buffer{}
	restore := redirectStderr(t, stderr)
	defer restore()

	_ = runMCPProxyDarwin(opts)
	restore()

	for _, marker := range []string{"--no-sandbox requested", "macOS .app helper"} {
		if strings.Contains(stderr.String(), marker) {
			t.Errorf("a non-helper command must not degrade; saw %q in stderr:\n%s", marker, stderr.String())
		}
	}
}

// TestStripLeadingNoSandboxFlag_LeadingRegion confirms the flag is picked up
// when it appears among sir-local flags before the wrapped command.
func TestStripLeadingNoSandboxFlag_LeadingRegion(t *testing.T) {
	args := []string{"--no-sandbox", "--allow-host", "api.example.com", "node", "server.js"}
	noSandbox, filtered := stripLeadingNoSandboxFlag(args)

	if !noSandbox {
		t.Fatal("--no-sandbox in leading region should be captured")
	}
	allowedHosts, command, cmdArgs, malformed := parseMCPProxyInvocation(filtered)
	if malformed {
		t.Fatalf("parse malformed after strip: %v / %v", allowedHosts, cmdArgs)
	}
	if len(allowedHosts) != 1 || allowedHosts[0] != "api.example.com" {
		t.Errorf("allowedHosts = %v, want [api.example.com]", allowedHosts)
	}
	if command != "node" {
		t.Errorf("command = %q, want node", command)
	}
	if len(cmdArgs) != 1 || cmdArgs[0] != "server.js" {
		t.Errorf("cmdArgs = %v, want [server.js]", cmdArgs)
	}
}

// TestStripLeadingNoSandboxFlag_AfterCommandIsChildArg is the security
// regression for the injection bypass codex caught: `--no-sandbox` passed
// AFTER the wrapped command must NOT be consumed by sir; it belongs to
// that command's argv. An attacker controlling an MCP config could
// otherwise force monitored mode by adding `--no-sandbox` to the child's
// args, and a globally-scoped strip loop would happily remove it.
func TestStripLeadingNoSandboxFlag_AfterCommandIsChildArg(t *testing.T) {
	args := []string{"/bin/sh", "-c", "/path/to/server", "--no-sandbox"}
	noSandbox, filtered := stripLeadingNoSandboxFlag(args)

	if noSandbox {
		t.Error("--no-sandbox AFTER the wrapped command MUST NOT enable monitored mode")
	}
	// The trailing --no-sandbox must survive as a child argv entry.
	if len(filtered) != 4 {
		t.Fatalf("filtered len = %d, want 4 (full passthrough): %v", len(filtered), filtered)
	}
	if filtered[3] != "--no-sandbox" {
		t.Errorf("trailing --no-sandbox was stripped; filtered = %v", filtered)
	}
}

// TestStripLeadingNoSandboxFlag_AllowHostValueIsNotMistakenForCommand
// checks that stripLeadingNoSandboxFlag correctly treats the argument to
// --allow-host as a value, not as the wrapped command. Otherwise a
// trailing `--no-sandbox` inside the leading region could be missed.
func TestStripLeadingNoSandboxFlag_AllowHostValueIsNotMistakenForCommand(t *testing.T) {
	args := []string{"--allow-host", "api.example.com", "--no-sandbox", "node", "server.js"}
	noSandbox, filtered := stripLeadingNoSandboxFlag(args)

	if !noSandbox {
		t.Error("--no-sandbox after --allow-host VALUE is still in leading region; should be captured")
	}
	if filtered[0] != "--allow-host" || filtered[1] != "api.example.com" {
		t.Errorf("--allow-host chunk was mangled: %v", filtered)
	}
	if filtered[len(filtered)-2] != "node" || filtered[len(filtered)-1] != "server.js" {
		t.Errorf("wrapped command+args were mangled: %v", filtered)
	}
}

// Satisfies the linter — imports used only by the other proxy tests.
var _ = exec.Command
var _ = syscall.SIGTERM
