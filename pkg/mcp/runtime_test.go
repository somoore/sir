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

func TestAssessProxyRuntimeNoSandboxDegradesOnDarwin(t *testing.T) {
	assessment := AssessProxyRuntime(ProxySpec{
		Wrapped:   true,
		NoSandbox: true,
	}, "darwin", true)

	if assessment.Mode != RuntimeNoSandboxMonitoringOnly {
		t.Fatalf("mode = %q, want %q (darwin_localhost_only must NOT be reported when --no-sandbox was passed)",
			assessment.Mode, RuntimeNoSandboxMonitoringOnly)
	}
	if !assessment.NeedsAttention {
		t.Fatal("expected --no-sandbox proxy to require operator attention")
	}
}

func TestAssessProxyRuntimeNoSandboxDegradesOnLinux(t *testing.T) {
	assessment := AssessProxyRuntime(ProxySpec{
		Wrapped:   true,
		NoSandbox: true,
	}, "linux", true)

	if assessment.Mode != RuntimeNoSandboxMonitoringOnly {
		t.Fatalf("mode = %q, want %q (linux_namespace_isolated must NOT be reported when --no-sandbox was passed)",
			assessment.Mode, RuntimeNoSandboxMonitoringOnly)
	}
	if !assessment.NeedsAttention {
		t.Fatal("expected --no-sandbox proxy to require operator attention")
	}
}

func TestClassifyProxyCapturesNoSandboxLeadingFlag(t *testing.T) {
	// `sir mcp-proxy --no-sandbox node server.js` must classify with
	// NoSandbox=true so inventory renders the runtime as degraded.
	spec := ClassifyProxy("sir", []string{"mcp-proxy", "--no-sandbox", "node", "server.js"})
	if !spec.Wrapped {
		t.Fatalf("expected Wrapped=true, got %+v", spec)
	}
	if !spec.NoSandbox {
		t.Fatalf("expected NoSandbox=true, got %+v", spec)
	}
	if spec.InnerCommand != "node" || len(spec.InnerArgs) != 1 || spec.InnerArgs[0] != "server.js" {
		t.Fatalf("inner command/args wrong: %+v", spec)
	}
	if spec.Malformed {
		t.Fatalf("unexpected Malformed=true: %+v", spec)
	}
}

func TestClassifyProxyDoesNotConsumeNoSandboxFromChildArgs(t *testing.T) {
	// `--no-sandbox` AFTER the wrapped command is an argument to the child
	// program, not a sir flag. It must stay in InnerArgs and must NOT flip
	// the sandbox-opt-out bit on the inventory record.
	spec := ClassifyProxy("sir", []string{"mcp-proxy", "node", "server.js", "--no-sandbox"})
	if !spec.Wrapped {
		t.Fatalf("expected Wrapped=true, got %+v", spec)
	}
	if spec.NoSandbox {
		t.Fatalf("NoSandbox must not be set from child argv: %+v", spec)
	}
	if spec.InnerCommand != "node" {
		t.Fatalf("inner command = %q, want node", spec.InnerCommand)
	}
	if len(spec.InnerArgs) != 2 || spec.InnerArgs[0] != "server.js" || spec.InnerArgs[1] != "--no-sandbox" {
		t.Fatalf("child --no-sandbox must be preserved as InnerArgs: %+v", spec.InnerArgs)
	}
}

func TestClassifyProxyNoSandboxWithAllowHost(t *testing.T) {
	// Leading flags can appear in any order; both --allow-host and
	// --no-sandbox must be recognized.
	spec := ClassifyProxy("sir", []string{
		"mcp-proxy", "--no-sandbox", "--allow-host", "api.example.com", "node", "server.js",
	})
	if !spec.NoSandbox {
		t.Fatalf("expected NoSandbox=true, got %+v", spec)
	}
	if len(spec.AllowedHosts) != 1 || spec.AllowedHosts[0] != "api.example.com" {
		t.Fatalf("allowed hosts wrong: %+v", spec.AllowedHosts)
	}
	if spec.InnerCommand != "node" {
		t.Fatalf("inner command = %q, want node", spec.InnerCommand)
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
