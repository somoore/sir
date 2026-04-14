package mcp

import "testing"

func TestIsMacAppHelperCommand(t *testing.T) {
	cases := []struct {
		name     string
		command  string
		args     []string
		wantHit  bool
		wantPath string
	}{
		{
			name:     "direct helper under MacOS",
			command:  "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer",
			wantHit:  true,
			wantPath: "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer",
		},
		{
			name:     "direct helper under XPCServices",
			command:  "/Applications/Foo.app/Contents/XPCServices/Bar.xpc/Contents/MacOS/Bar",
			wantHit:  true,
			wantPath: "/Applications/Foo.app/Contents/XPCServices/Bar.xpc/Contents/MacOS/Bar",
		},
		{
			name:     "bash -c with single-quoted app path",
			command:  "/bin/bash",
			args:     []string{"-c", "'/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer'"},
			wantHit:  true,
			wantPath: "/Applications/Hopper Disassembler.app/Contents/MacOS/HopperMCPServer",
		},
		{
			name:     "sh -c with double-quoted app path",
			command:  "/bin/sh",
			args:     []string{"-c", `"/Applications/Foo.app/Contents/MacOS/Helper"`},
			wantHit:  true,
			wantPath: "/Applications/Foo.app/Contents/MacOS/Helper",
		},
		{
			name:     "bash -c with unquoted app path",
			command:  "/bin/bash",
			args:     []string{"-c", "/Applications/Foo.app/Contents/MacOS/Helper"},
			wantHit:  true,
			wantPath: "/Applications/Foo.app/Contents/MacOS/Helper",
		},
		{
			name:    "bash -c with complex shell payload stays sandboxed",
			command: "/bin/bash",
			args:    []string{"-c", "export FOO=bar && /Applications/Foo.app/Contents/MacOS/Helper"},
			wantHit: false,
		},
		{
			name:    "node server not a helper",
			command: "/usr/local/bin/node",
			args:    []string{"/path/to/server.js"},
			wantHit: false,
		},
		{
			name:    "python MCP server not a helper",
			command: "/usr/bin/python3",
			args:    []string{"-m", "my_mcp_server"},
			wantHit: false,
		},
		{
			name:    "direct binary under /Applications but not in .app bundle",
			command: "/Applications/standalone-binary",
			wantHit: false,
		},
		{
			name:    "resource under .app but not in MacOS/XPCServices",
			command: "/Applications/Foo.app/Contents/Resources/script.sh",
			wantHit: false,
		},
		{
			name:    "bash -c with pipe stays sandboxed",
			command: "/bin/bash",
			args:    []string{"-c", "'/Applications/Foo.app/Contents/MacOS/Helper' | grep foo"},
			wantHit: false,
		},
		{
			name:    "shell wrapper with extra args stays sandboxed",
			command: "/bin/bash",
			args:    []string{"-l", "-c", "'/Applications/Foo.app/Contents/MacOS/Helper'"},
			wantHit: false,
		},
		{
			name:    "empty args",
			command: "",
			wantHit: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, path := IsMacAppHelperCommand(tc.command, tc.args)
			if hit != tc.wantHit {
				t.Errorf("hit=%v, want %v (path=%q)", hit, tc.wantHit, path)
			}
			if tc.wantHit && path != tc.wantPath {
				t.Errorf("path=%q, want %q", path, tc.wantPath)
			}
		})
	}
}
