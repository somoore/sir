package mcp

import (
	"os/exec"
)

// ConfigScope identifies one MCP configuration surface.
type ConfigScope string

const (
	ConfigProjectLocal ConfigScope = "project_local"
	ConfigClaudeGlobal ConfigScope = "claude_global"
	ConfigGeminiGlobal ConfigScope = "gemini_global"
)

// ProxySpec describes whether an MCP server entry is already wrapped by sir.
type ProxySpec struct {
	Wrapped      bool
	SirCommand   string
	AllowedHosts []string
	// NoSandbox is true when the sir mcp-proxy invocation carries
	// --no-sandbox in the leading-flags region, which disables sandbox-exec
	// (macOS) / unshare (Linux) and drops to credential-scanning-only mode.
	// Tracked here so inventory and runtime assessment don't report the
	// server as hardened when it was explicitly opted out.
	NoSandbox    bool
	InnerCommand string
	InnerArgs    []string
	Malformed    bool
}

// ServerInventory is sir's normalized view of one MCP server entry.
type ServerInventory struct {
	Name        string
	SourcePath  string
	SourceLabel string
	Scope       ConfigScope
	Command     string
	Args        []string
	HasCommand  bool
	Proxy       ProxySpec
}

// InventoryError records an MCP config that could not be parsed.
type InventoryError struct {
	Path string
	Err  error
}

// InventoryReport is the aggregate inventory for one or more MCP config files.
type InventoryReport struct {
	Servers []ServerInventory
	Errors  []InventoryError
}

// RewriteResult describes one rewritten MCP config file.
type RewriteResult struct {
	Path    string
	Servers []string
}

// RuntimeMode is the assessed process/network hardening mode for an MCP server.
type RuntimeMode string

const (
	RuntimeRaw                       RuntimeMode = "raw"
	RuntimeNonCommandTransport       RuntimeMode = "non_command_transport"
	RuntimeDarwinLocalhostOnly       RuntimeMode = "darwin_localhost_only"
	RuntimeDarwinBroadOutbound       RuntimeMode = "darwin_broad_outbound"
	RuntimeLinuxNamespaceIsolated    RuntimeMode = "linux_namespace_isolated"
	RuntimeLinuxAllowHostUnsupported RuntimeMode = "linux_allow_host_unsupported"
	RuntimeMonitoringOnly            RuntimeMode = "monitoring_only"
	// RuntimeNoSandboxMonitoringOnly means the proxy wrapper exists but the
	// operator opted out with --no-sandbox; sir only scans credentials and
	// forwards signals. Reported separately from RuntimeMonitoringOnly so
	// operators can tell an intentional opt-out from an environment that
	// lacks sandbox support.
	RuntimeNoSandboxMonitoringOnly RuntimeMode = "no_sandbox_monitoring_only"
)

// RuntimeAssessment is the operator-facing posture summary for an MCP entry.
type RuntimeAssessment struct {
	Mode           RuntimeMode
	Summary        string
	Warning        string
	NeedsAttention bool
}

// InventoryFile identifies one MCP config file to inspect.
type InventoryFile struct {
	Path  string
	Label string
	Scope ConfigScope
}

var execLookPath = exec.LookPath
