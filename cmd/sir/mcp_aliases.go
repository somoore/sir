package main

import (
	"os/exec"

	mcppkg "github.com/somoore/sir/pkg/mcp"
)

type mcpConfigScope = mcppkg.ConfigScope

const (
	mcpConfigProjectLocal = mcppkg.ConfigProjectLocal
	mcpConfigClaudeGlobal = mcppkg.ConfigClaudeGlobal
	mcpConfigGeminiGlobal = mcppkg.ConfigGeminiGlobal
)

type mcpProxySpec = mcppkg.ProxySpec
type mcpServerInventory = mcppkg.ServerInventory
type mcpInventoryError = mcppkg.InventoryError
type mcpInventoryReport = mcppkg.InventoryReport
type mcpRewriteResult = mcppkg.RewriteResult
type mcpRuntimeMode = mcppkg.RuntimeMode
type mcpRuntimeAssessment = mcppkg.RuntimeAssessment

const (
	mcpRuntimeRaw                       = mcppkg.RuntimeRaw
	mcpRuntimeNonCommandTransport       = mcppkg.RuntimeNonCommandTransport
	mcpRuntimeDarwinLocalhostOnly       = mcppkg.RuntimeDarwinLocalhostOnly
	mcpRuntimeDarwinBroadOutbound       = mcppkg.RuntimeDarwinBroadOutbound
	mcpRuntimeLinuxNamespaceIsolated    = mcppkg.RuntimeLinuxNamespaceIsolated
	mcpRuntimeLinuxAllowHostUnsupported = mcppkg.RuntimeLinuxAllowHostUnsupported
	mcpRuntimeMonitoringOnly            = mcppkg.RuntimeMonitoringOnly
)

func discoverMCPServers(projectRoot string) []string {
	return mcppkg.DiscoverServerNames(projectRoot)
}

func discoverMCPInventory(projectRoot string) mcpInventoryReport {
	return mcppkg.DiscoverInventory(projectRoot)
}

func discoverMCPInventoryForScopes(projectRoot string, scopes map[mcpConfigScope]bool) mcpInventoryReport {
	return mcppkg.DiscoverInventoryForScopes(projectRoot, scopes)
}

func approvedMCPServerNames(servers []mcpServerInventory) []string {
	return mcppkg.ApprovedServerNames(servers)
}

func planMCPProxyRewrites(servers []mcpServerInventory) []mcpServerInventory {
	return mcppkg.PlanProxyRewrites(servers)
}

func rewriteDiscoveredMCPServers(servers []mcpServerInventory, sirPath string) ([]mcpRewriteResult, error) {
	return mcppkg.RewriteDiscoveredServers(servers, sirPath)
}

func readJSONFileMap(path string) (map[string]interface{}, error) {
	return mcppkg.ReadJSONFileMap(path)
}

func writeJSONFileMap(path string, doc map[string]interface{}) error {
	return mcppkg.WriteJSONFileMap(path, doc)
}

func interfaceSliceToStrings(v interface{}) ([]string, bool) {
	return mcppkg.InterfaceSliceToStrings(v)
}

type mcpInventoryFile = mcppkg.InventoryFile

func readMCPInventoryFile(file mcpInventoryFile) ([]mcpServerInventory, error) {
	return mcppkg.ReadInventoryFile(file)
}

func classifyMCPProxy(command string, args []string) mcpProxySpec {
	return mcppkg.ClassifyProxy(command, args)
}

func parseMCPProxyInvocation(args []string) ([]string, string, []string, bool) {
	return mcppkg.ParseProxyInvocation(args)
}

func assessMCPProxyRuntime(proxy mcpProxySpec, goos string, hasUnshare bool) mcpRuntimeAssessment {
	return mcppkg.AssessProxyRuntime(proxy, goos, hasUnshare)
}

var execLookPath = exec.LookPath

func hasUnshareBinary() bool {
	_, err := execLookPath("unshare")
	return err == nil
}
