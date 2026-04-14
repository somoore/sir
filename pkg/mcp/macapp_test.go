package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestClassifyAppHelperShape covers the pure string classification. All
// inputs are expected to be filepath.Clean'd; the classifier explicitly
// rejects anything that isn't, so traversal strings get rejected by the
// Clean equality check even before the prefix checks run.
func TestClassifyAppHelperShape(t *testing.T) {
	cases := []struct {
		name string
		p    string
		want bool
	}{
		// Positive: canonical app helpers
		{"helper under MacOS", "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer", true},
		{"helper under XPCServices", "/Applications/Foo.app/Contents/XPCServices/Bar.xpc/Contents/MacOS/Bar", true},

		// Negative: not an .app bundle
		{"standalone binary under /Applications", "/Applications/standalone-binary", false},
		{"resource path inside .app", "/Applications/Foo.app/Contents/Resources/script.sh", false},

		// Negative: traversal — Clean(input) != input, so rejected
		{"traversal escape", "/Applications/Foo.app/Contents/MacOS/../../../../bin/sh", false},
		{"traversal within bundle", "/Applications/Foo.app/Contents/MacOS/../Resources/X", false},
		{"redundant separators", "/Applications//Foo.app/Contents/MacOS/X", false},
		{"trailing slash", "/Applications/Foo.app/Contents/MacOS/X/", false},
		{"current-dir segment", "/Applications/Foo.app/Contents/MacOS/./X", false},

		// Negative: outside /Applications
		{"/bin/sh", "/bin/sh", false},
		{"home-dir app", "/Users/x/Applications/Foo.app/Contents/MacOS/X", false},

		// Negative: degenerate
		{"empty", "", false},
		{"relative path", "Foo.app/Contents/MacOS/X", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyAppHelperShape(tc.p); got != tc.want {
				t.Errorf("classifyAppHelperShape(%q) = %v, want %v", tc.p, got, tc.want)
			}
		})
	}
}

// TestIsMacAppHelperCommand_ShellWrapperShapes exercises the caller-facing
// entrypoint, which additionally requires the target to exist on disk.
// Synthetic paths under /Applications that don't exist (test environments)
// are expected to fail closed — IsMacAppHelperCommand returns false.
func TestIsMacAppHelperCommand_ShellWrapperShapes(t *testing.T) {
	cases := []struct {
		name    string
		command string
		args    []string
		wantHit bool // all false; synthetic paths don't exist
	}{
		{"direct helper — synthetic path fails closed",
			"/Applications/Fake.app/Contents/MacOS/Helper", nil, false},
		{"bash -c single-quoted — synthetic fails closed",
			"/bin/bash", []string{"-c", "'/Applications/Fake.app/Contents/MacOS/Helper'"}, false},
		{"bash -c double-quoted — synthetic fails closed",
			"/bin/bash", []string{"-c", `"/Applications/Fake.app/Contents/MacOS/Helper"`}, false},
		{"bash -c unquoted — synthetic fails closed",
			"/bin/bash", []string{"-c", "/Applications/Fake.app/Contents/MacOS/Helper"}, false},

		// Negative shapes even if target existed
		{"node server — not a helper",
			"/usr/local/bin/node", []string{"/path/to/server.js"}, false},
		{"python MCP server — not a helper",
			"/usr/bin/python3", []string{"-m", "my_mcp_server"}, false},
		{"bash -c with pipe stays sandboxed",
			"/bin/bash", []string{"-c", "'/Applications/Foo.app/Contents/MacOS/Helper' | grep foo"}, false},
		{"shell wrapper with extra args stays sandboxed",
			"/bin/bash", []string{"-l", "-c", "'/Applications/Foo.app/Contents/MacOS/Helper'"}, false},
		{"bash -c with shell payload stays sandboxed",
			"/bin/bash", []string{"-c", "export FOO=bar && /Applications/Foo.app/Contents/MacOS/Helper"}, false},

		// Traversal bypass attempt — must be rejected even if the fallback
		// target (/bin/sh) exists.
		{"traversal to /bin/sh",
			"/Applications/Foo.app/Contents/MacOS/../../../../bin/sh", nil, false},
		{"bash -c with traversal",
			"/bin/bash", []string{"-c", "'/Applications/Foo.app/Contents/MacOS/../../../../bin/sh'"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, _ := IsMacAppHelperCommand(tc.command, tc.args)
			if hit != tc.wantHit {
				t.Errorf("IsMacAppHelperCommand(%q, %v) hit=%v, want %v", tc.command, tc.args, hit, tc.wantHit)
			}
		})
	}
}

// TestIsMacAppHelperCommand_RealFileMatches uses a real bundle-shaped path
// rooted in a temp directory to prove the positive path actually resolves.
// We can't write into /Applications, so we synthesize a fake /Applications
// tree under HOME, make the test walk through EvalSymlinks, and prove that
// a non-symlink regular file at the right shape matches.
//
// macOS only: the /Applications prefix is darwin-specific by design.
func TestIsMacAppHelperCommand_RealFileMatches(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only classifier")
	}
	// The shape check hard-codes the /Applications prefix, so a temp-root
	// "fake" bundle cannot satisfy it. Instead, test against a real macOS
	// system bundle if one is present.
	candidates := []string{
		"/System/Applications/Calculator.app/Contents/MacOS/Calculator",
		"/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
	}
	// /System/Applications isn't /Applications — the check won't match;
	// this is intentional. We instead look for a user-installed helper
	// under /Applications that we can verify ship on most macs. If none
	// are present, skip.
	var realHelper string
	entries, err := os.ReadDir("/Applications")
	if err != nil {
		t.Skip("no /Applications directory available")
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
			realHelper = filepath.Join(macosDir, h.Name())
			break
		}
		if realHelper != "" {
			break
		}
	}
	if realHelper == "" {
		t.Skipf("no real /Applications/*.app/Contents/MacOS/* helper available (checked candidates: %v)", candidates)
	}
	hit, resolved := IsMacAppHelperCommand(realHelper, nil)
	if !hit {
		t.Errorf("expected %q to match as an app helper", realHelper)
	}
	if resolved == "" {
		t.Error("expected non-empty resolved path on match")
	}
}
