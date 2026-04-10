package lifecycle

import (
	"os"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/posture"
	"github.com/somoore/sir/pkg/session"
)

type PostureIntegrityDrift struct {
	NonHookFiles []string
	HookFiles    []posture.AgentHookFile
}

type GlobalHookIntegrityDrift struct {
	CurrentHash      string
	CurrentHashKnown bool
	Changed          []posture.AgentHookFile
	BaselineErr      error
}

func DetectPostureIntegrityDrift(projectRoot string, state *session.State, l *lease.Lease) PostureIntegrityDrift {
	tampered := posture.CheckPostureIntegrity(projectRoot, state, l)
	drift := PostureIntegrityDrift{
		NonHookFiles: make([]string, 0, len(tampered)),
		HookFiles:    make([]posture.AgentHookFile, 0, len(tampered)),
	}
	for _, target := range tampered {
		if hookFile, ok := posture.LookupAgentHookFileByRelativePath(target); ok {
			drift.HookFiles = append(drift.HookFiles, hookFile)
			continue
		}
		drift.NonHookFiles = append(drift.NonHookFiles, target)
	}
	return drift
}

func DetectGlobalHookIntegrityDrift(state *session.State) *GlobalHookIntegrityDrift {
	if state == nil || state.GlobalHookHash == "" {
		return nil
	}
	currentHash, hashErr := posture.HashGlobalHooksFile()
	globalDrift := (hashErr == nil && currentHash != state.GlobalHookHash) || os.IsNotExist(hashErr)
	if !globalDrift {
		return nil
	}
	changed, detectErr := posture.DetectChangedGlobalHooksStrict()
	return &GlobalHookIntegrityDrift{
		CurrentHash:      currentHash,
		CurrentHashKnown: hashErr == nil,
		Changed:          changed,
		BaselineErr:      detectErr,
	}
}
