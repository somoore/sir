package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	hookclassify "github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func evaluateMCPCapabilityScope(payload *HookPayload, l *lease.Lease, state *session.State, projectRoot string) (*HookResponse, bool) {
	if !isToolMCP(payload.ToolName) {
		return nil, false
	}
	serverName := extractMCPServerName(payload.ToolName)
	if !isApprovedMCPServer(serverName, l) {
		return nil, false
	}
	scope, ok := l.FindMCPCapabilityScope(serverName)
	if !ok {
		return nil, false
	}
	if reason := mcpScopeViolation(payload.ToolName, payload.ToolInput, scope, projectRoot); reason != "" {
		if _, ok := state.ConsumeApprovalGrant("mcp_scope", serverName); ok {
			return nil, false
		}
		entry := &ledger.Entry{
			ToolName: payload.ToolName,
			Verb:     "mcp_scope",
			Target:   serverName,
			Decision: string(policy.VerdictAsk),
			Reason:   reason,
		}
		if err := ledger.Append(projectRoot, entry); err != nil {
			fmt.Fprintf(os.Stderr, "sir: ledger append (mcp scope): %v\n", err)
		}
		saveSessionBestEffort(state)
		return &HookResponse{
			Decision: policy.VerdictAsk,
			Reason:   fmt.Sprintf("MCP server %q is outside its configured capability scope: %s", serverName, reason),
		}, true
	}
	return nil, false
}

func mcpScopeViolation(toolName string, input map[string]interface{}, scope lease.MCPCapabilityScope, projectRoot string) string {
	if len(scope.Tools) > 0 {
		toolLeaf := extractMCPToolLeaf(toolName)
		found := false
		for _, allowed := range scope.Tools {
			if strings.EqualFold(strings.TrimSpace(allowed), toolLeaf) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Sprintf("tool %q is not in allowed tool list", toolLeaf)
		}
	}
	if !scope.AllowShell && hookclassify.FirstShellLikeValue(input) != "" {
		return "shell-like argument present but allow_shell=false"
	}
	if !scope.AllowNetwork && len(hookclassify.ExtractMCPURLs(input)) > 0 {
		return "URL argument present but allow_network=false"
	}
	if path := hookclassify.FirstWriteLikePath(input); path != "" {
		if !scope.AllowWrite {
			return "write-like path argument present but allow_write=false"
		}
		if len(scope.Roots) > 0 && !pathWithinAnyRoot(projectRoot, path, scope.Roots) {
			return fmt.Sprintf("path %q is outside allowed roots", path)
		}
	}
	return ""
}

func extractMCPToolLeaf(toolName string) string {
	parts := strings.SplitN(toolName, "__", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return toolName
}

func pathWithinAnyRoot(projectRoot, raw string, roots []string) bool {
	target := ResolveTarget(projectRoot, raw)
	if target == "" {
		target = raw
	}
	target = filepath.Clean(target)
	for _, root := range roots {
		root = strings.TrimSpace(root)
		if root == "" {
			continue
		}
		resolvedRoot := ResolveTarget(projectRoot, root)
		if resolvedRoot == "" {
			resolvedRoot = root
		}
		resolvedRoot = filepath.Clean(resolvedRoot)
		if target == resolvedRoot || strings.HasPrefix(target, resolvedRoot+string(filepath.Separator)) {
			return true
		}
	}
	return false
}
