package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCmdMCPStatus_DefaultsToInventoryView(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"project-raw":{"command":"node","args":["server.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"strict-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "node", "strict.js"},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdMCP(env.projectRoot, nil)
	})

	if !strings.Contains(out, "sir mcp status") {
		t.Fatalf("expected default mcp command to render status header, got:\n%s", out)
	}
	if !strings.Contains(out, "project-raw") || !strings.Contains(out, "raw (no sir mcp-proxy)") {
		t.Fatalf("expected raw MCP inventory in output, got:\n%s", out)
	}
	if !strings.Contains(out, "Run 'sir mcp wrap' to rewrite them through sir mcp-proxy.") {
		t.Fatalf("expected wrap remediation in output, got:\n%s", out)
	}
}

func TestCmdMCPWrap_RewritesRawServers(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":{"project-raw":{"command":"node","args":["server.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"global-raw": map[string]interface{}{
				"command": "python3",
				"args":    []string{"global.py"},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdMCP(env.projectRoot, []string{"wrap", "--yes"})
	})

	if !strings.Contains(out, "Rewrote") {
		t.Fatalf("expected rewrite summary in output, got:\n%s", out)
	}

	projectDoc, err := readJSONFileMap(filepath.Join(env.projectRoot, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	projectEntry := projectDoc["mcpServers"].(map[string]interface{})["project-raw"].(map[string]interface{})
	if projectEntry["command"] != "sir" {
		t.Fatalf("expected project server to be rewritten to sir, got %#v", projectEntry["command"])
	}

	globalDoc := env.readSettingsJSON()
	globalEntry := globalDoc["mcpServers"].(map[string]interface{})["global-raw"].(map[string]interface{})
	if globalEntry["command"] != "sir" {
		t.Fatalf("expected global server to be rewritten to sir, got %#v", globalEntry["command"])
	}
}

func TestCmdMCPWrap_NoRawServersDoesNotRewrite(t *testing.T) {
	env := newTestEnv(t)

	env.writeSettingsJSON(map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"strict-proxy": map[string]interface{}{
				"command": "sir",
				"args":    []string{"mcp-proxy", "node", "strict.js"},
			},
		},
	})

	out := captureStdout(t, func() {
		cmdMCP(env.projectRoot, []string{"wrap", "--yes"})
	})

	if !strings.Contains(out, "No raw command-based MCP servers need wrapping.") {
		t.Fatalf("expected no-op wrap message, got:\n%s", out)
	}
}

func TestCmdMCPStatus_CodexHasNoSupportedMCPSurface(t *testing.T) {
	env := newTestEnv(t)

	out := captureStdout(t, func() {
		cmdMCPStatus(env.projectRoot, "codex")
	})

	if !strings.Contains(out, "codex does not expose a supported MCP config surface in sir today.") {
		t.Fatalf("expected codex MCP surface explanation, got:\n%s", out)
	}
}

func TestCmdMCPWrap_ParseErrorsDoNotClaimClean(t *testing.T) {
	env := newTestEnv(t)

	if err := os.WriteFile(filepath.Join(env.projectRoot, ".mcp.json"), []byte(`{"mcpServers":`), 0o644); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdMCP(env.projectRoot, []string{"wrap", "--yes"})
	})

	if !strings.Contains(out, "No readable raw command-based MCP servers were found.") {
		t.Fatalf("expected parse-error warning in output, got:\n%s", out)
	}
	if strings.Contains(out, "No raw command-based MCP servers need wrapping.") {
		t.Fatalf("wrap should not claim MCP surfaces are clean when config files were unreadable:\n%s", out)
	}
}

func TestCmdMCPWrap_PromptEOFDoesNotImplyYes(t *testing.T) {
	env := newTestEnv(t)

	configPath := filepath.Join(env.projectRoot, ".mcp.json")
	if err := os.WriteFile(configPath, []byte(`{"mcpServers":{"project-raw":{"command":"node","args":["server.js"]}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	origStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = r
	t.Cleanup(func() {
		os.Stdin = origStdin
		r.Close()
	})

	out := captureStdout(t, func() {
		cmdMCP(env.projectRoot, []string{"wrap"})
	})

	if !strings.Contains(out, "MCP wrap cancelled (no interactive confirmation received).") {
		t.Fatalf("expected EOF cancellation message, got:\n%s", out)
	}

	projectDoc, err := readJSONFileMap(configPath)
	if err != nil {
		t.Fatal(err)
	}
	projectEntry := projectDoc["mcpServers"].(map[string]interface{})["project-raw"].(map[string]interface{})
	if projectEntry["command"] != "node" {
		t.Fatalf("expected project server to remain unwrapped after EOF cancellation, got %#v", projectEntry["command"])
	}
}
