package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyMCPProxy(t *testing.T) {
	spec := classifyMCPProxy("/usr/local/bin/sir", []string{"mcp-proxy", "--allow-host", "api.slack.com", "node", "server.js"})
	if !spec.Wrapped {
		t.Fatal("expected wrapper to be detected")
	}
	if spec.SirCommand != "/usr/local/bin/sir" {
		t.Fatalf("expected SirCommand to be preserved, got %q", spec.SirCommand)
	}
	if len(spec.AllowedHosts) != 1 || spec.AllowedHosts[0] != "api.slack.com" {
		t.Fatalf("expected allowed host to be parsed, got %v", spec.AllowedHosts)
	}
	if spec.InnerCommand != "node" {
		t.Fatalf("expected inner command node, got %q", spec.InnerCommand)
	}
	if len(spec.InnerArgs) != 1 || spec.InnerArgs[0] != "server.js" {
		t.Fatalf("expected inner args to be preserved, got %v", spec.InnerArgs)
	}
}

func TestClassifyMCPProxy_MultipleAllowHosts(t *testing.T) {
	spec := classifyMCPProxy("/usr/local/bin/sir", []string{"mcp-proxy", "--allow-host", "api.slack.com", "--allow-host", "slack.com", "node", "server.js"})
	if !spec.Wrapped {
		t.Fatal("expected wrapper to be detected")
	}
	if len(spec.AllowedHosts) != 2 || spec.AllowedHosts[0] != "api.slack.com" || spec.AllowedHosts[1] != "slack.com" {
		t.Fatalf("expected repeated --allow-host values to be preserved, got %v", spec.AllowedHosts)
	}
	if spec.InnerCommand != "node" {
		t.Fatalf("expected inner command node, got %q", spec.InnerCommand)
	}
}

func TestMCPServerInventory_RuntimeAssessment_NonCommandEntry(t *testing.T) {
	server := mcpServerInventory{
		Name:       "remote-server",
		SourcePath: "/tmp/.mcp.json",
		Scope:      mcpConfigProjectLocal,
		HasCommand: false,
	}

	assessment := server.RuntimeAssessment()
	if assessment.Mode != mcpRuntimeNonCommandTransport {
		t.Fatalf("expected non-command runtime mode, got %q", assessment.Mode)
	}
	if assessment.Summary != "non-command transport (sir mcp-proxy not applicable)" {
		t.Fatalf("unexpected summary: %q", assessment.Summary)
	}
}

func TestReadMCPInventoryFile_MalformedWrappedEntry(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"broken":{"command":"sir","args":["mcp-proxy",7,"server.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, err := readMCPInventoryFile(mcpInventoryFile{Path: path, Label: ".mcp.json", Scope: mcpConfigProjectLocal})
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected one server, got %d", len(servers))
	}
	if !servers[0].Proxy.Wrapped || !servers[0].Proxy.Malformed {
		t.Fatalf("expected malformed wrapped proxy to stay identifiable, got %+v", servers[0].Proxy)
	}
}

func TestAssessMCPProxyRuntime_MalformedNonArrayArgsStayMalformed(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"broken":{"command":"sir","args":"oops"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	servers, err := readMCPInventoryFile(mcpInventoryFile{Path: path, Label: ".mcp.json", Scope: mcpConfigProjectLocal})
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected one server, got %d", len(servers))
	}

	assessment := assessMCPProxyRuntime(servers[0].Proxy, "darwin", false)
	if assessment.Mode != mcpRuntimeMonitoringOnly {
		t.Fatalf("expected malformed wrapper mode, got %q", assessment.Mode)
	}
	if assessment.Summary != "proxied (malformed sir mcp-proxy invocation)" {
		t.Fatalf("unexpected summary: %q", assessment.Summary)
	}
}

func TestAssessMCPProxyRuntime(t *testing.T) {
	tests := []struct {
		name       string
		proxy      mcpProxySpec
		goos       string
		hasUnshare bool
		wantMode   mcpRuntimeMode
	}{
		{
			name:       "darwin strict",
			proxy:      mcpProxySpec{Wrapped: true},
			goos:       "darwin",
			hasUnshare: false,
			wantMode:   mcpRuntimeDarwinLocalhostOnly,
		},
		{
			name:       "darwin allow host broadens",
			proxy:      mcpProxySpec{Wrapped: true, AllowedHosts: []string{"api.slack.com"}},
			goos:       "darwin",
			hasUnshare: false,
			wantMode:   mcpRuntimeDarwinBroadOutbound,
		},
		{
			name:       "linux strict",
			proxy:      mcpProxySpec{Wrapped: true},
			goos:       "linux",
			hasUnshare: true,
			wantMode:   mcpRuntimeLinuxNamespaceIsolated,
		},
		{
			name:       "linux allow host unsupported",
			proxy:      mcpProxySpec{Wrapped: true, AllowedHosts: []string{"api.slack.com"}},
			goos:       "linux",
			hasUnshare: true,
			wantMode:   mcpRuntimeLinuxAllowHostUnsupported,
		},
		{
			name:       "linux monitoring fallback",
			proxy:      mcpProxySpec{Wrapped: true},
			goos:       "linux",
			hasUnshare: false,
			wantMode:   mcpRuntimeMonitoringOnly,
		},
		{
			name:       "unsupported monitoring only",
			proxy:      mcpProxySpec{Wrapped: true},
			goos:       "windows",
			hasUnshare: false,
			wantMode:   mcpRuntimeMonitoringOnly,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := assessMCPProxyRuntime(tt.proxy, tt.goos, tt.hasUnshare)
			if got.Mode != tt.wantMode {
				t.Fatalf("expected mode %q, got %q (%s)", tt.wantMode, got.Mode, got.Summary)
			}
		})
	}
}
