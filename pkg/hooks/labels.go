// Package hooks implements the sir hook handlers for Claude Code.
package hooks

import (
	"strings"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/hooks/classify"
	"github.com/somoore/sir/pkg/lease"
)

// LabelsForTarget returns IFC labels for a given target path based on the lease.
// projectRoot is used to resolve symlinks and traversal paths so that a symlink
// to .env gets labeled "secret" (not "public") in the IFC trail.
func LabelsForTarget(target string, l *lease.Lease, projectRoot ...string) core.Label {
	root := ""
	if len(projectRoot) > 0 {
		root = projectRoot[0]
	}

	isSensitive := false
	isPosture := false
	if root != "" {
		isSensitive = classify.IsSensitivePathResolvedIn(root, target, l)
		isPosture = classify.IsPostureFileResolvedIn(root, target, l)
	} else {
		isSensitive = classify.IsSensitivePath(target, l)
		isPosture = classify.IsPostureFile(target, l)
	}

	if isSensitive {
		return core.Label{Sensitivity: "secret", Trust: "trusted", Provenance: "user"}
	}
	if isPosture {
		return core.Label{Sensitivity: "internal", Trust: "trusted", Provenance: "user"}
	}

	clean := strings.TrimSpace(target)
	for _, dir := range []string{"node_modules/", ".venv/", "vendor/", "target/", "_build/"} {
		if strings.HasPrefix(clean, dir) || strings.Contains(clean, "/"+dir) {
			return core.Label{
				Sensitivity: "public",
				Trust:       "verified_origin",
				Provenance:  "external_package",
			}
		}
	}
	for _, dir := range []string{"src/", "lib/", "app/", "cmd/", "internal/", "tests/", "test/"} {
		if strings.HasPrefix(clean, dir) || strings.Contains(clean, "/"+dir) {
			return core.Label{
				Sensitivity: "internal",
				Trust:       "trusted",
				Provenance:  "user",
			}
		}
	}
	return core.Label{Sensitivity: "public", Trust: "trusted", Provenance: "user"}
}

// ResolveTarget canonicalizes a target path against projectRoot.
func ResolveTarget(projectRoot, target string) string {
	return classify.ResolveTarget(projectRoot, target)
}

// LabelsForMCPTool returns labels for an MCP tool call.
func LabelsForMCPTool() core.Label {
	return core.Label{Sensitivity: "public", Trust: "verified_origin", Provenance: "mcp_tool"}
}

// LabelsForAgent returns labels for agent-generated content.
func LabelsForAgent() core.Label {
	return core.Label{Sensitivity: "public", Trust: "verified_internal", Provenance: "agent"}
}

// IsPostureFile checks if a target path is a posture file.
func IsPostureFile(target string, l *lease.Lease) bool {
	return classify.IsPostureFile(target, l)
}

// IsSensitivePath checks if a target path is sensitive (secret-labeled).
func IsSensitivePath(target string, l *lease.Lease) bool {
	return classify.IsSensitivePath(target, l)
}

// IsSensitivePathResolved is like IsSensitivePath but resolves symlinks first.
func IsSensitivePathResolved(target string, l *lease.Lease) bool {
	return classify.IsSensitivePathResolved(target, l)
}

// IsSensitivePathResolvedIn canonicalizes traversal paths against projectRoot before matching.
func IsSensitivePathResolvedIn(projectRoot, target string, l *lease.Lease) bool {
	return classify.IsSensitivePathResolvedIn(projectRoot, target, l)
}

// IsPostureFileResolved is like IsPostureFile but resolves symlinks first.
func IsPostureFileResolved(target string, l *lease.Lease) bool {
	return classify.IsPostureFileResolved(target, l)
}

// IsPostureFileResolvedIn canonicalizes traversal paths against projectRoot before matching.
func IsPostureFileResolvedIn(projectRoot, target string, l *lease.Lease) bool {
	return classify.IsPostureFileResolvedIn(projectRoot, target, l)
}

// ClassifyNetworkDest classifies a network destination as loopback, approved, or external.
func ClassifyNetworkDest(target string, l *lease.Lease) string {
	return classify.ClassifyNetworkDest(target, l)
}

// ClassifyGitRemote classifies a git remote as approved or unapproved.
func ClassifyGitRemote(cmd string, l *lease.Lease) string {
	return classify.ClassifyGitRemote(cmd, l)
}

// IsEphemeralExec returns true for npx commands (ephemeral remote code execution).
func IsEphemeralExec(cmd string) bool {
	return classify.IsEphemeralExec(cmd)
}

// extractHost extracts the hostname from a URL or host:port string.
func extractHost(target string) string {
	return classify.ExtractHost(target)
}

// ExtractGitRemote extracts the remote name from a `git push` command.
func ExtractGitRemote(cmd string) string {
	return classify.ExtractGitRemote(cmd)
}

// extractGitRemote is the unexported alias retained so the rest of the
// package (and any tests that were pinned on the old name) keeps compiling.
func extractGitRemote(cmd string) string {
	return ExtractGitRemote(cmd)
}
