package hooks

import (
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

func labelsForEvaluation(payload *HookPayload, intent Intent, l *lease.Lease, projectRoot string) core.Label {
	switch {
	case intent.Verb == policy.VerbReadRef || intent.Verb == policy.VerbStageWrite:
		return LabelsForTarget(intent.Target, l, projectRoot)
	case payload.ToolName == "Agent":
		return LabelsForAgent()
	case isToolMCP(payload.ToolName):
		return LabelsForMCPTool()
	default:
		return core.Label{
			Sensitivity: "public",
			Trust:       "trusted",
			Provenance:  "user",
		}
	}
}

func prepareInstallEvaluation(intent Intent, state *session.State, l *lease.Lease, projectRoot string) (*HookResponse, bool) {
	if !intent.IsInstall {
		return nil, false
	}
	sentinelHashes, lockfileHash := installSentinelHashes(projectRoot, l, intent.Manager)
	state.SetPendingInstall(intent.Target, intent.Manager, sentinelHashes, lockfileHash)

	pkgName := extractPackageName(intent.Target, intent.Manager)
	if pkgName == "" || isPackageInLockfile(projectRoot, intent.Manager, pkgName) {
		return nil, false
	}
	saveSessionBestEffort(state)
	return &HookResponse{
		Decision: policy.VerdictAsk,
		Reason:   FormatAskInstall(pkgName, intent.Manager),
	}, true
}

func installSentinelHashes(projectRoot string, l *lease.Lease, manager string) (map[string]string, string) {
	sentinelHashes := HashSentinelFiles(projectRoot, l.SentinelFilesForInstall)
	lockfiles := LockfileForManager(manager)
	if len(lockfiles) == 0 {
		return sentinelHashes, ""
	}
	lockfileHashes := HashSentinelFiles(projectRoot, lockfiles)
	for _, hash := range lockfileHashes {
		if hash != "" {
			return sentinelHashes, hash
		}
	}
	return sentinelHashes, ""
}
