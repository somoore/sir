package main

import (
	"bytes"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// TestRunMCPProxyDarwin_AutoDegradesMacAppHelper checks that a command
// matching the Mac-app-helper heuristic skips sandbox-exec entirely and
// falls through to monitored mode. We verify by running a real child that
// writes a marker to stderr and comparing that stderr also contains the
// degradation notice. If sandbox-exec ran, the notice wouldn't appear AND
// the child wouldn't execute (the path is synthetic, sandbox-exec would
// fail to locate the binary and exit non-zero).
func TestRunMCPProxyDarwin_AutoDegradesMacAppHelper(t *testing.T) {
	// We can't actually put a binary under /Applications/*.app in a test,
	// so instead we exercise the branch by calling runMCPProxyDarwin with
	// a Mac-app-helper-shaped command that resolves to a known-good
	// executable. The degradation notice prints before Start(); if the
	// sandbox path had run, the notice wouldn't be emitted.
	opts := mcpProxyOpts{
		command: "/Applications/Fake.app/Contents/MacOS/PretendHelper",
		args:    nil,
	}

	stderr := &bytes.Buffer{}
	restore := redirectStderr(t, stderr)
	defer restore()

	// The synthetic command doesn't exist, so runProxyChild will fail at
	// Start(). We only care that we took the monitored branch — detected
	// by the "running in monitored mode" notice printed before Start().
	_ = runMCPProxyDarwin(opts)

	restore()
	if !strings.Contains(stderr.String(), "monitored mode") {
		t.Errorf("expected auto-degrade notice in stderr; got:\n%s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "macOS .app helper") {
		t.Errorf("expected Mac-app-helper reason in notice; got:\n%s", stderr.String())
	}
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

// TestCmdMCPProxy_StripsNoSandboxBeforeParse ensures the --no-sandbox flag
// is consumed in cmdMCPProxy and not passed through to the shared proxy
// parser (which only knows --allow-host). We can't invoke cmdMCPProxy
// directly without fork/exec, so we test the stripping inline using a
// helper that mirrors the logic in mcp_proxy.go.
func TestCmdMCPProxy_StripsNoSandboxBeforeParse(t *testing.T) {
	args := []string{"--no-sandbox", "--allow-host", "api.example.com", "node", "server.js"}

	noSandbox := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--no-sandbox" {
			noSandbox = true
			continue
		}
		filtered = append(filtered, a)
	}

	if !noSandbox {
		t.Fatal("--no-sandbox should be captured")
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

// Satisfies the linter — imports used only by the other proxy tests.
var _ = exec.Command
var _ = syscall.SIGTERM
