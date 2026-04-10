package hooks

import (
	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

type AgentHookFile = posture.AgentHookFile

func ExtractManagedSubtree(raw []byte, managedKey string) ([]byte, error) {
	return posture.ExtractManagedSubtree(raw, managedKey)
}

func ExtractHooksSubtree(raw []byte) ([]byte, error) {
	return posture.ExtractHooksSubtree(raw)
}

func NewAgentHookFile(ag agent.Agent, homeDir string) AgentHookFile {
	return posture.NewAgentHookFile(ag, homeDir)
}

func LookupAgentHookFileByRelativePath(relPath string) (AgentHookFile, bool) {
	return posture.LookupAgentHookFileByRelativePath(relPath)
}

func hashGlobalHooksFile() (string, error) {
	return posture.HashGlobalHooksFile()
}

func managedGlobalHooksHash() (string, bool, error) {
	return posture.ManagedGlobalHooksHash()
}

func HashGlobalHooks(projectRoot string) (string, error) {
	return posture.HashGlobalHooks(projectRoot)
}

func HashLease(projectRoot string) (string, error) {
	return posture.HashLease(projectRoot)
}

func hashLeaseFile(projectRoot string) (string, error) {
	return posture.HashLeaseFile(projectRoot)
}

func VerifyLeaseIntegrity(projectRoot string, state *session.State) bool {
	return posture.VerifyLeaseIntegrity(projectRoot, state)
}

func CheckPostureIntegrity(projectRoot string, state *session.State, l *lease.Lease) []string {
	return posture.CheckPostureIntegrity(projectRoot, state, l)
}

func HashSentinelFiles(root string, files []string) map[string]string {
	return posture.HashSentinelFiles(root, files)
}

func CompareSentinelHashes(before, after map[string]string) []string {
	return posture.CompareSentinelHashes(before, after)
}

func DetectChangedGlobalHooks() []AgentHookFile {
	return posture.DetectChangedGlobalHooks()
}

func DetectChangedGlobalHooksStrict() ([]AgentHookFile, error) {
	return posture.DetectChangedGlobalHooksStrict()
}

func AutoRestoreAgentHookFile(f AgentHookFile) bool {
	return posture.AutoRestoreAgentHookFile(f)
}

func FormatChangedHookTargets(changed []AgentHookFile) string {
	return posture.FormatChangedHookTargets(changed)
}

func joinWithComma(parts []string) string {
	return posture.JoinWithComma(parts)
}

func appendHookTamperEntry(projectRoot, toolName string, f AgentHookFile, decision, reason string, restored bool, diffSummary string) (*ledger.Entry, error) {
	return posture.AppendHookTamperEntry(projectRoot, toolName, f, decision, reason, restored, diffSummary)
}

func managedHookDiffSummary(f AgentHookFile) string {
	return posture.ManagedHookDiffSummary(f)
}
