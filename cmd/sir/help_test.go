package main

import "testing"

func TestWantsHelp(t *testing.T) {
	if !wantsHelp([]string{"--agent", "claude", "--help"}) {
		t.Error("--help anywhere should be detected")
	}
	if !wantsHelp([]string{"-h"}) {
		t.Error("-h should be detected")
	}
	if wantsHelp([]string{"--agent", "claude"}) {
		t.Error("no help flag should not be detected")
	}
}

// The destructive/mutating commands must have a help entry so `--help` shows it
// instead of executing them.
func TestCommandHelp_CoversDestructiveCommands(t *testing.T) {
	for _, cmd := range []string{"install", "uninstall", "setup", "doctor", "allow-host", "allow-remote", "trust", "approve", "policy", "mcp"} {
		if _, ok := commandHelp[cmd]; !ok {
			t.Errorf("missing --help text for mutating command %q", cmd)
		}
	}
}

func TestPassthroughCommandsNotIntercepted(t *testing.T) {
	// mcp-proxy/run/guard forward args; --help must reach the subprocess.
	for _, cmd := range []string{"mcp-proxy", "run", "guard"} {
		if !passthroughCommands[cmd] {
			t.Errorf("%q should be a passthrough command", cmd)
		}
	}
	if passthroughCommands["uninstall"] {
		t.Error("uninstall must NOT be passthrough (its --help must be intercepted)")
	}
}
