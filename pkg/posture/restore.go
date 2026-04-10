package posture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/session"
)

// DetectChangedGlobalHooks returns the agent hook files whose current managed
// subtree differs from the canonical backup.
func DetectChangedGlobalHooks() []AgentHookFile {
	changed, err := DetectChangedGlobalHooksStrict()
	if err != nil {
		return nil
	}
	return changed
}

// DetectChangedGlobalHooksStrict returns the set of changed hook files or a
// hard error when managed mode cannot establish a trustworthy hook baseline.
func DetectChangedGlobalHooksStrict() ([]AgentHookFile, error) {
	files, err := knownAgentHookFiles()
	if err != nil {
		return nil, err
	}
	policy, err := session.LoadManagedPolicy()
	if err != nil {
		return nil, err
	}
	var changed []AgentHookFile
	for _, f := range files {
		canonical, ok, canErr := managedHookBaselineBytesWithPolicy(f, policy)
		if canErr != nil {
			return nil, canErr
		}
		if !ok {
			if err := verifyManagedHookCoverage(f, policy); err != nil {
				return nil, err
			}
			continue
		}
		current, curErr := os.ReadFile(f.AbsPath)
		if curErr != nil {
			if os.IsNotExist(curErr) {
				changed = append(changed, f)
			}
			continue
		}

		liveHooks, liveErr := ExtractManagedSubtree(current, f.managedSubtreeKey())
		canonHooks, canSubErr := extractCanonicalManagedSubtreeBytes(canonical, f.managedSubtreeKey())
		if liveErr != nil || canSubErr != nil {
			if !bytes.Equal(current, canonical) {
				changed = append(changed, f)
			}
			continue
		}
		if !bytes.Equal(liveHooks, canonHooks) {
			changed = append(changed, f)
		}
	}
	return changed, nil
}

func extractCanonicalManagedSubtreeBytes(canonical []byte, managedKey string) ([]byte, error) {
	if managedKey != "" {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(canonical, &obj); err != nil {
			return nil, err
		}
		if _, hasManagedKey := obj[managedKey]; hasManagedKey {
			return ExtractManagedSubtree(canonical, managedKey)
		}
	}
	var canon interface{}
	if err := json.Unmarshal(canonical, &canon); err != nil {
		return nil, err
	}
	return json.Marshal(canon)
}

// AutoRestoreAgentHookFile restores the managed subtree for a drifted hook
// file from the canonical backup or managed policy baseline.
func AutoRestoreAgentHookFile(f AgentHookFile) bool {
	canonRaw, ok, err := managedHookBaselineBytes(f)
	if err != nil || !ok {
		return false
	}
	return autoRestoreAgentHookFileFromBytes(f, canonRaw)
}

func autoRestoreAgentHookFileFromBytes(f AgentHookFile, canonRaw []byte) bool {
	var canonHooks interface{}
	if f.managedSubtreeKey() == "" {
		if err := json.Unmarshal(canonRaw, &canonHooks); err != nil {
			return false
		}
	} else {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(canonRaw, &obj); err == nil {
			if wrapped, hasManagedKey := obj[f.managedSubtreeKey()]; hasManagedKey {
				if err := json.Unmarshal(wrapped, &canonHooks); err != nil {
					return false
				}
			} else if err := json.Unmarshal(canonRaw, &canonHooks); err != nil {
				return false
			}
		} else {
			return false
		}
	}

	liveData, liveErr := os.ReadFile(f.AbsPath)
	liveObj := make(map[string]interface{})
	if liveErr == nil {
		_ = json.Unmarshal(liveData, &liveObj)
	}
	var (
		merged []byte
		err    error
	)
	if f.managedSubtreeKey() == "" {
		merged, err = json.MarshalIndent(canonHooks, "", "  ")
		if err != nil {
			return false
		}
	} else {
		liveObj[f.managedSubtreeKey()] = canonHooks
		merged, err = json.MarshalIndent(liveObj, "", "  ")
		if err != nil {
			return false
		}
	}
	if err := os.MkdirAll(filepath.Dir(f.AbsPath), 0o750); err != nil {
		return false
	}
	return os.WriteFile(f.AbsPath, merged, 0o600) == nil
}

func managedHookBaselineBytes(f AgentHookFile) ([]byte, bool, error) {
	policy, err := session.LoadManagedPolicy()
	if err != nil {
		return nil, false, err
	}
	return managedHookBaselineBytesWithPolicy(f, policy)
}

func managedHookBaselineBytesWithPolicy(f AgentHookFile, policy *session.ManagedPolicy) ([]byte, bool, error) {
	if policy != nil {
		raw, ok := policy.HookSubtree(string(agentIDForHookFile(f)))
		if !ok {
			return nil, false, nil
		}
		return raw, true, nil
	}
	raw, err := os.ReadFile(f.CanonicalPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return raw, true, nil
}

func verifyManagedHookCoverage(f AgentHookFile, policy *session.ManagedPolicy) error {
	if policy == nil {
		return nil
	}
	if _, err := os.Stat(f.AbsPath); err == nil {
		return fmt.Errorf("managed policy %s does not cover installed hook file %s", policy.PolicyVersion, f.DisplayPath)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", f.DisplayPath, err)
	}
	return nil
}

func agentIDForHookFile(f AgentHookFile) agent.AgentID {
	for _, ag := range agent.All() {
		spec := ag.GetSpec()
		if spec != nil && spec.ConfigFile == f.RelativePath {
			return ag.ID()
		}
	}
	return ""
}

// FormatChangedHookTargets produces a user-facing list of changed hook files.
func FormatChangedHookTargets(changed []AgentHookFile) string {
	if len(changed) == 0 {
		return "global hooks"
	}
	parts := make([]string, 0, len(changed))
	for _, f := range changed {
		parts = append(parts, f.DisplayPath)
	}
	return JoinWithComma(parts)
}

// JoinWithComma formats a compact comma-separated human-readable list.
func JoinWithComma(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := parts[0]
	for _, p := range parts[1:] {
		out += ", " + p
	}
	return out
}
