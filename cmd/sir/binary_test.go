package main

import "testing"

// TestIsSirHookCommand_RecognizesAnyBinaryPath documents the regression
// fix for hook duplication: previously isSirHookCommand only matched the
// current process's binary path (sirBinaryPath + " guard "), so re-running
// `sir install` from a different binary path failed to recognize the
// existing hook entries written by an earlier install at a different
// path. The filter would skip them, install would append the new entries,
// and both stayed in the settings file forever — firing twice on every
// tool call.
//
// The fix matches by structure: any command whose first token's basename
// is `sir` (or `sir.exe`) and whose second token is `guard` is treated as
// a sir hook regardless of the absolute path. This catches stale entries
// from prior installs and lets the new install replace them cleanly.
func TestIsSirHookCommand_RecognizesAnyBinaryPath(t *testing.T) {
	// Pin sirBinaryPath so the test does not depend on where the test
	// binary lives. Restore at end.
	orig := sirBinaryPath
	sirBinaryPath = "/Users/test/.local/bin/sir"
	t.Cleanup(func() { sirBinaryPath = orig })

	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		// --- positive: sir hook commands at various binary paths ---
		{"current path",
			"/Users/test/.local/bin/sir guard evaluate", true},
		{"different absolute path (regression)",
			"/private/tmp/sir-dev/sir guard evaluate", true},
		{"system path",
			"/usr/local/bin/sir guard post-evaluate", true},
		{"bare sir on PATH",
			"sir guard evaluate", true},
		{"with --agent flag",
			"/opt/homebrew/bin/sir guard evaluate --agent gemini", true},
		{"all known subcommands",
			"/usr/bin/sir guard session-summary --agent codex", true},
		{"windows .exe basename",
			"C:/sir/sir.exe guard evaluate", true},

		// --- negative: not sir hook commands ---
		{"empty",
			"", false},
		{"non-sir binary",
			"/usr/local/bin/other guard evaluate", false},
		{"sir but not guard",
			"/usr/local/bin/sir status", false},
		{"single token",
			"sir", false},
		{"second token is not guard",
			"sir install --yes", false},
		{"sir as substring of basename",
			"/usr/local/bin/sirius guard evaluate", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSirHookCommand(tc.cmd); got != tc.want {
				t.Errorf("isSirHookCommand(%q) = %v, want %v", tc.cmd, got, tc.want)
			}
		})
	}
}
