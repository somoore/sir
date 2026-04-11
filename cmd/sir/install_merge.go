package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/session"
)

func generatedHooksConfigForAgent(ag agent.Agent, mode string) (map[string]interface{}, error) {
	mb, ok := ag.(agent.MapBuilder)
	if !ok {
		return nil, fmt.Errorf("%s: adapter does not implement MapBuilder", ag.Name())
	}

	hooksConfig, err := mb.GenerateHooksConfigMap(sirBinaryPath, mode)
	if err != nil {
		return nil, fmt.Errorf("generate hooks for %s: %w", ag.Name(), err)
	}
	return hooksConfig, nil
}

func validateGeneratedHooksPolicy(ag agent.Agent, hooksConfig map[string]interface{}, policy *session.ManagedPolicy) error {
	if policy == nil {
		return nil
	}

	subtreeKey := ag.GetSpec().ConfigStrategy.ManagedSubtreeKey
	generatedBytes, err := json.Marshal(hooksConfig)
	if err != nil {
		return fmt.Errorf("marshal generated hooks for %s: %w", ag.Name(), err)
	}
	generatedSubtree, err := hooks.ExtractManagedSubtree(generatedBytes, subtreeKey)
	if err != nil {
		return fmt.Errorf("extract generated hooks subtree for %s: %w", ag.Name(), err)
	}
	wantHash, ok := policy.ManagedHookHashes[string(ag.ID())]
	if !ok {
		return fmt.Errorf("managed policy %s does not define managed_hook_hashes[%s]", policy.PolicyVersion, ag.ID())
	}
	gotHash, err := session.HashManagedHooksSubtree(generatedSubtree)
	if err != nil {
		return fmt.Errorf("hash generated hooks for %s: %w", ag.Name(), err)
	}
	if gotHash != wantHash {
		return fmt.Errorf("%s hooks do not match managed policy %s; generated hash %s, expected %s from %s",
			ag.Name(), policy.PolicyVersion, gotHash, wantHash, policy.ManagedPolicySourcePath())
	}
	return nil
}

func filterSirHookEntries(entries []interface{}, layout agent.ConfigLayout) ([]interface{}, bool, error) {
	if layout != agent.ConfigLayoutMatcherGroups {
		return nil, false, fmt.Errorf("unsupported config layout: %s", layout)
	}

	var filtered []interface{}
	modified := false
	for _, entry := range entries {
		kept := true
		if em, ok := entry.(map[string]interface{}); ok {
			if innerHooks, ok := em["hooks"].([]interface{}); ok {
				var innerFiltered []interface{}
				for _, ih := range innerHooks {
					if ihm, ok := ih.(map[string]interface{}); ok {
						if cmd, ok := ihm["command"].(string); ok && isSirHookCommand(cmd) {
							modified = true
							continue
						}
					}
					innerFiltered = append(innerFiltered, ih)
				}
				if len(innerFiltered) == 0 {
					kept = false
				} else {
					em["hooks"] = innerFiltered
				}
			} else if cmd, ok := em["command"].(string); ok && isSirHookCommand(cmd) {
				kept = false
				modified = true
			}
		}
		if kept {
			filtered = append(filtered, entry)
		}
	}
	return filtered, modified, nil
}

// installForAgent merges sir's hook entries into the given agent's config
// file, writes a per-agent canonical backup copy, and performs any
// agent-specific extra steps (e.g. Codex config.toml feature flag).
func installForAgent(ag agent.Agent, mode, homeDir string, skipPreview bool, policy *session.ManagedPolicy) error {
	configPath := ag.ConfigPath()
	if configPath == "" {
		return fmt.Errorf("%s: could not determine config path", ag.Name())
	}

	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		return fmt.Errorf("create %s config dir: %w", ag.Name(), err)
	}

	hooksConfig, err := generatedHooksConfigForAgent(ag, mode)
	if err != nil {
		return err
	}
	if err := validateGeneratedHooksPolicy(ag, hooksConfig, policy); err != nil {
		return err
	}
	subtreeKey := ag.GetSpec().ConfigStrategy.ManagedSubtreeKey

	existingSettings := make(map[string]interface{})
	if existing, readErr := os.ReadFile(configPath); readErr == nil {
		_ = json.Unmarshal(existing, &existingSettings)
	}

	existingHooks := managedSubtreeFromConfig(existingSettings, subtreeKey)
	if existingHooks == nil {
		existingHooks = make(map[string]interface{})
	}
	sirHooks := managedSubtreeFromConfig(hooksConfig, subtreeKey)
	layout := ag.GetSpec().ConfigStrategy.EffectiveLayout()
	for hookType, existing := range existingHooks {
		existingArr, ok := existing.([]interface{})
		if !ok {
			// Preserve forward-compatible metadata under the managed subtree.
			continue
		}
		filtered, _, err := filterSirHookEntries(existingArr, layout)
		if err != nil {
			return fmt.Errorf("filter existing %s hooks for %s: %w", hookType, ag.Name(), err)
		}
		if len(filtered) == 0 {
			delete(existingHooks, hookType)
			continue
		}
		existingHooks[hookType] = filtered
	}
	for hookType, newEntries := range sirHooks {
		newArr, ok := newEntries.([]interface{})
		if !ok {
			existingHooks[hookType] = newEntries
			continue
		}
		existing, _ := existingHooks[hookType].([]interface{})
		filtered, _, err := filterSirHookEntries(existing, layout)
		if err != nil {
			return fmt.Errorf("filter merged %s hooks for %s: %w", hookType, ag.Name(), err)
		}
		existingHooks[hookType] = append(newArr, filtered...)
	}
	existingSettings = setManagedSubtree(existingSettings, subtreeKey, existingHooks)

	data, err := json.MarshalIndent(existingSettings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s config: %w", ag.Name(), err)
	}
	if err := os.WriteFile(configPath, data, 0o644); err != nil {
		return fmt.Errorf("write %s config: %w", ag.Name(), err)
	}

	canonicalBytes, err := hooks.ExtractManagedSubtree(data, subtreeKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not extract hooks subtree for %s canonical: %v\n", ag.Name(), err)
		canonicalBytes = data
	}
	canonicalPath := ag.GetSpec().ConfigStrategy.CanonicalBackupPath(homeDir)
	if err := os.WriteFile(canonicalPath, canonicalBytes, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not save canonical copy for %s: %v\n", ag.Name(), err)
	}

	if fn := ag.GetSpec().PostInstallFunc; fn != nil {
		fn(homeDir, skipPreview)
	}

	fmt.Printf("  %s hooks written to %s\n", ag.Name(), configPath)
	return nil
}

// uninstallForAgent removes sir entries from the agent's config file and
// returns true if it modified anything. The file itself is always left in
// place even if the hooks map becomes empty — the user may want to
// re-install later and deleting third-party config files would be rude.
// Per-agent canonical copies are preserved for forensic value.
func uninstallForAgent(ag agent.Agent) (bool, error) {
	configPath := ag.ConfigPath()
	if configPath == "" {
		return false, nil
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return false, fmt.Errorf("read %s: %w", configPath, err)
		}
		return false, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return false, fmt.Errorf("parse %s: %w", configPath, err)
	}
	modified := false
	subtreeKey := ag.GetSpec().ConfigStrategy.ManagedSubtreeKey
	layout := ag.GetSpec().ConfigStrategy.EffectiveLayout()
	if hooksSection := managedSubtreeFromConfig(config, subtreeKey); hooksSection != nil {
		for eventName, val := range hooksSection {
			arr, ok := val.([]interface{})
			if !ok {
				continue
			}
			filtered, changed, err := filterSirHookEntries(arr, layout)
			if err != nil {
				return false, fmt.Errorf("filter %s hooks for %s: %w", eventName, ag.Name(), err)
			}
			if changed {
				modified = true
			}
			if len(filtered) == 0 {
				delete(hooksSection, eventName)
				continue
			}
			hooksSection[eventName] = filtered
		}
		config = setManagedSubtree(config, subtreeKey, hooksSection)
	}
	if !modified {
		return false, nil
	}
	newData, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return false, fmt.Errorf("marshal %s: %w", configPath, err)
	}
	if err := os.WriteFile(configPath, newData, 0o644); err != nil {
		return false, fmt.Errorf("write %s: %w", configPath, err)
	}
	fmt.Printf("sir hooks removed from %s (%s).\n", configPath, ag.Name())
	return true, nil
}
