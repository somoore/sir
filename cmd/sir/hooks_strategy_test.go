package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

func TestDetectRegisteredHookEventsAt_CustomManagedKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "settings.json")
	raw := `{
  "customHooks": {
    "BeforeTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "` + sirBinaryPath + ` guard evaluate --agent demo",
            "timeout": 5
          }
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	registered, err := detectRegisteredHookEventsAt(configPath, agent.ConfigStrategy{
		ManagedSubtreeKey: "customHooks",
		Layout:            agent.ConfigLayoutMatcherGroups,
	})
	if err != nil {
		t.Fatalf("detectRegisteredHookEventsAt: %v", err)
	}
	if !registered["BeforeTool"] {
		t.Fatalf("BeforeTool was not detected in custom managed subtree: %+v", registered)
	}
}

func TestValidateHookSchemaAt_CustomManagedKey(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "settings.json")
	raw := `{
  "customHooks": {
    "BeforeTool": [
      {
        "command": "` + sirBinaryPath + ` guard evaluate --agent demo"
      }
    ]
  }
}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}

	invalid, err := validateHookSchemaAt(configPath, agent.ConfigStrategy{
		ManagedSubtreeKey: "customHooks",
		Layout:            agent.ConfigLayoutMatcherGroups,
	})
	if err != nil {
		t.Fatalf("validateHookSchemaAt: %v", err)
	}
	if len(invalid) != 1 || invalid[0] != "BeforeTool" {
		t.Fatalf("expected BeforeTool schema failure, got %+v", invalid)
	}
}
