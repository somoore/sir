package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAssessProxyRuntimeLinuxAllowHostUnsupported(t *testing.T) {
	assessment := AssessProxyRuntime(ProxySpec{
		Wrapped:      true,
		AllowedHosts: []string{"api.slack.com"},
	}, "linux", true)

	if assessment.Mode != RuntimeLinuxAllowHostUnsupported {
		t.Fatalf("mode = %q, want %q", assessment.Mode, RuntimeLinuxAllowHostUnsupported)
	}
	if !assessment.NeedsAttention {
		t.Fatal("expected linux allow-host assessment to require attention")
	}
}

func TestReadInventoryFileClassifiesWrappedServers(t *testing.T) {
	projectRoot := t.TempDir()
	path := filepath.Join(projectRoot, ".mcp.json")
	doc := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"strict-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "node", "strict.js"},
			},
		},
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshal inventory file: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write inventory file: %v", err)
	}

	servers, err := ReadInventoryFile(InventoryFile{
		Path:  path,
		Label: ".mcp.json",
		Scope: ConfigProjectLocal,
	})
	if err != nil {
		t.Fatalf("ReadInventoryFile: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("servers = %d, want 1", len(servers))
	}
	if !servers[0].Proxy.Wrapped {
		t.Fatalf("expected wrapped proxy classification, got %+v", servers[0].Proxy)
	}
}
