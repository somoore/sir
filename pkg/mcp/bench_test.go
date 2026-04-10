package mcp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkDiscoverInventory(b *testing.B) {
	homeDir := b.TempDir()
	projectRoot := b.TempDir()
	b.Setenv("HOME", homeDir)

	write := func(path string, doc map[string]interface{}) {
		b.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			b.Fatalf("mkdir %s: %v", path, err)
		}
		data, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			b.Fatalf("marshal %s: %v", path, err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			b.Fatalf("write %s: %v", path, err)
		}
	}

	projectDoc := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"raw-server": map[string]interface{}{
				"command": "node",
				"args":    []string{"raw.js"},
			},
			"strict-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "node", "strict.js"},
			},
			"degraded-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "--allow-host", "api.slack.com", "node", "degraded.js"},
			},
		},
	}
	write(filepath.Join(projectRoot, ".mcp.json"), projectDoc)
	write(filepath.Join(homeDir, ".claude", "settings.json"), projectDoc)
	write(filepath.Join(homeDir, ".gemini", "settings.json"), projectDoc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := DiscoverInventory(projectRoot)
		if len(report.Errors) != 0 {
			b.Fatalf("DiscoverInventory returned errors: %+v", report.Errors)
		}
		if got := len(report.Servers); got != 9 {
			b.Fatalf("DiscoverInventory returned %d servers, want 9", got)
		}
	}
}
