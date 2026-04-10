package main

import (
	"encoding/json"
	"os"

	"github.com/somoore/sir/pkg/agent"
)

// allHookEvents lists every hook event that sir registers.
// This must stay in sync with generateHooksConfig.
var allHookEvents = []string{
	"PreToolUse",
	"PostToolUse",
	"SubagentStart",
	"UserPromptSubmit",
	"SessionStart",
	"ConfigChange",
	"InstructionsLoaded",
	"Stop",
	"SessionEnd",
	"Elicitation",
}

// detectRegisteredHookEvents reads ~/.claude/settings.json and returns
// a map of hook event names that have at least one sir guard command registered.
// Kept as a thin wrapper over detectRegisteredHookEventsAt for backward
// compatibility with existing callers that assume the Claude Code config path.
func detectRegisteredHookEvents() (map[string]bool, error) {
	return detectRegisteredHookEventsFor(agent.NewClaudeAgent())
}

func detectRegisteredHookEventsFor(ag agent.Agent) (map[string]bool, error) {
	return detectRegisteredHookEventsAt(ag.ConfigPath(), ag.GetSpec().ConfigStrategy)
}

// detectRegisteredHookEventsAt reads an arbitrary agent config file and
// returns the set of hook event names with at least one sir guard command
// registered inside the managed subtree.
func detectRegisteredHookEventsAt(configPath string, strategy agent.ConfigStrategy) (map[string]bool, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	hooksSection := managedSubtreeFromConfig(config, strategy.ManagedSubtreeKey)
	if hooksSection == nil {
		return map[string]bool{}, nil
	}

	registered := map[string]bool{}
	for eventName, val := range hooksSection {
		arr, _ := val.([]interface{})
		for _, entry := range arr {
			switch strategy.EffectiveLayout() {
			case agent.ConfigLayoutMatcherGroups:
				em, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				// Claude Code requires: { "hooks": [{ "type": "command", "command": "..." }] }
				// Optionally with "matcher" for tool-scoped events.
				innerHooks, ok := em["hooks"].([]interface{})
				if !ok {
					continue // Flat format is invalid — Claude Code won't load it
				}
				for _, ih := range innerHooks {
					ihm, ok := ih.(map[string]interface{})
					if !ok {
						continue
					}
					if cmd, ok := ihm["command"].(string); ok && isSirHookCommand(cmd) {
						registered[eventName] = true
					}
				}
			default:
				panic("unsupported config layout: " + string(strategy.EffectiveLayout()))
			}
		}
	}
	return registered, nil
}

// validateHookSchema checks that every sir hook entry in ~/.claude/settings.json
// uses the correct Claude Code schema: [{ hooks: [{ type, command, timeout }] }].
// Returns a list of events with invalid (flat) format that Claude Code will reject.
// Thin wrapper over validateHookSchemaAt for backward compatibility.
func validateHookSchema() (invalidEvents []string, err error) {
	return validateHookSchemaFor(agent.NewClaudeAgent())
}

func validateHookSchemaFor(ag agent.Agent) (invalidEvents []string, err error) {
	return validateHookSchemaAt(ag.ConfigPath(), ag.GetSpec().ConfigStrategy)
}

// validateHookSchemaAt validates hook schema against any agent's config
// file. Both Claude Code and Codex require the same matcher-group nested
// format: [{ hooks: [{ type, command, timeout }] }]. The flat format is
// silently rejected by both runtimes.
func validateHookSchemaAt(configPath string, strategy agent.ConfigStrategy) (invalidEvents []string, err error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	hooksSection := managedSubtreeFromConfig(config, strategy.ManagedSubtreeKey)
	if hooksSection == nil {
		return nil, nil
	}

	for eventName, val := range hooksSection {
		arr, _ := val.([]interface{})
		for _, entry := range arr {
			switch strategy.EffectiveLayout() {
			case agent.ConfigLayoutMatcherGroups:
				em, ok := entry.(map[string]interface{})
				if !ok {
					continue
				}
				// Check if this is a sir hook with the WRONG (flat) format.
				// Flat format: { "type": "command", "command": "sir guard ..." }
				// Correct format: { "hooks": [{ "type": "command", "command": "sir guard ..." }] }
				if cmd, ok := em["command"].(string); ok && isSirHookCommand(cmd) {
					if _, hasHooksWrapper := em["hooks"]; !hasHooksWrapper {
						invalidEvents = append(invalidEvents, eventName)
					}
				}
			default:
				panic("unsupported config layout: " + string(strategy.EffectiveLayout()))
			}
		}
	}
	return invalidEvents, nil
}

// generateHooksConfig returns the Claude Code hooks config as a
// map[string]interface{}, kept as a legacy helper for tests and the install
// merge loop that still expects Claude's []interface{} inner shape. New
// install paths should call the agent adapter directly (see
// installForAgent in install.go) so multi-agent dispatch stays centralized.
func generateHooksConfig(mode string) map[string]interface{} {
	ag := &agent.ClaudeAgent{}
	return ag.GenerateHooksConfigMap(sirBinaryPath, mode)
}

func managedSubtreeFromConfig(config map[string]interface{}, managedKey string) map[string]interface{} {
	if managedKey == "" {
		return config
	}
	subtree, _ := config[managedKey].(map[string]interface{})
	return subtree
}

func setManagedSubtree(config map[string]interface{}, managedKey string, subtree map[string]interface{}) map[string]interface{} {
	if managedKey == "" {
		return subtree
	}
	config[managedKey] = subtree
	return config
}
