package mcp

import (
	"fmt"
	"runtime"
)

// RuntimeAssessment reports the effective runtime hardening posture for this
// MCP server entry on the current host platform.
func (s ServerInventory) RuntimeAssessment() RuntimeAssessment {
	if !s.HasCommand {
		return RuntimeAssessment{
			Mode:           RuntimeNonCommandTransport,
			Summary:        "non-command transport (sir mcp-proxy not applicable)",
			Warning:        "this MCP entry does not launch a local command, so sir cannot add process-level MCP hardening here",
			NeedsAttention: true,
		}
	}
	return AssessProxyRuntime(s.Proxy, runtime.GOOS, HasUnshareBinary())
}

// AssessProxyRuntime summarizes the process/network hardening of a sir
// mcp-proxy wrapper on the given platform.
func AssessProxyRuntime(proxy ProxySpec, goos string, hasUnshare bool) RuntimeAssessment {
	if proxy.Malformed {
		return RuntimeAssessment{
			Mode:           RuntimeMonitoringOnly,
			Summary:        "proxied (malformed sir mcp-proxy invocation)",
			Warning:        "sir mcp-proxy wrapper is malformed; inspect the command and args manually",
			NeedsAttention: true,
		}
	}
	if !proxy.Wrapped {
		return RuntimeAssessment{
			Mode:           RuntimeRaw,
			Summary:        "raw (no sir mcp-proxy)",
			Warning:        "not wrapped with sir mcp-proxy; re-run `sir install` to add OS-level MCP hardening",
			NeedsAttention: true,
		}
	}

	switch goos {
	case "darwin":
		if len(proxy.AllowedHosts) > 0 {
			return RuntimeAssessment{
				Mode:           RuntimeDarwinBroadOutbound,
				Summary:        "proxied (macOS broad outbound allow; --allow-host cannot scope egress)",
				Warning:        "macOS sandbox-exec cannot allow specific hosts; any --allow-host broadens egress to all outbound destinations",
				NeedsAttention: true,
			}
		}
		return RuntimeAssessment{
			Mode:    RuntimeDarwinLocalhostOnly,
			Summary: "proxied (macOS localhost-only egress, writes restricted)",
		}
	case "linux":
		if !hasUnshare {
			return RuntimeAssessment{
				Mode:           RuntimeMonitoringOnly,
				Summary:        "proxied (monitoring only; Linux network sandbox unavailable)",
				Warning:        "Linux `unshare` is unavailable, so sir can only monitor stderr for this MCP server",
				NeedsAttention: true,
			}
		}
		if len(proxy.AllowedHosts) > 0 {
			return RuntimeAssessment{
				Mode:           RuntimeLinuxAllowHostUnsupported,
				Summary:        "proxied (Linux namespace isolation; --allow-host unsupported)",
				Warning:        "Linux `unshare --net` cannot allow specific hosts; the configured --allow-host values are ignored",
				NeedsAttention: true,
			}
		}
		return RuntimeAssessment{
			Mode:    RuntimeLinuxNamespaceIsolated,
			Summary: "proxied (Linux network namespace isolation)",
		}
	default:
		return RuntimeAssessment{
			Mode:           RuntimeMonitoringOnly,
			Summary:        fmt.Sprintf("proxied (monitoring only; no %s OS sandbox support)", goos),
			Warning:        fmt.Sprintf("%s does not provide an MCP network sandbox here; sir only monitors stderr for credential leakage", goos),
			NeedsAttention: true,
		}
	}
}

// HasUnshareBinary reports whether Linux namespace isolation is available.
func HasUnshareBinary() bool {
	_, err := execLookPath("unshare")
	return err == nil
}
