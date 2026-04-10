package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

type fakeAgent struct {
	spec agent.AgentSpec
}

func newFakeAgent() *fakeAgent {
	return &fakeAgent{
		spec: agent.AgentSpec{
			ID:         "fake",
			Name:       "Fake Agent",
			ConfigFile: ".fake/settings.json",
			ConfigStrategy: agent.ConfigStrategy{
				ManagedSubtreeKey:   "customHooks",
				Layout:              agent.ConfigLayoutMatcherGroups,
				CanonicalBackupFile: "hooks-canonical-fake.json",
			},
			SupportedSIREvents:  []string{"BeforeTool"},
			SupportedWireEvents: []string{"BeforeTool"},
			HookRegistrations: []agent.HookRegistration{
				{Event: "BeforeTool", Matcher: ".*", Command: "guard evaluate", Timeout: 5},
			},
		},
	}
}

func (f *fakeAgent) ID() agent.AgentID { return f.spec.ID }
func (f *fakeAgent) Name() string      { return f.spec.Name }
func (f *fakeAgent) ParsePreToolUse([]byte) (*agent.HookPayload, error) {
	return nil, nil
}
func (f *fakeAgent) ParsePostToolUse([]byte) (*agent.HookPayload, error) {
	return nil, nil
}
func (f *fakeAgent) FormatPreToolUseResponse(string, string) ([]byte, error) {
	return nil, nil
}
func (f *fakeAgent) FormatPostToolUseResponse(string, string) ([]byte, error) {
	return nil, nil
}
func (f *fakeAgent) FormatLifecycleResponse(string, string, string, string) ([]byte, error) {
	return nil, nil
}
func (f *fakeAgent) SupportedEvents() []string { return f.spec.SupportedWireEvents }
func (f *fakeAgent) ConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, f.spec.ConfigFile)
}
func (f *fakeAgent) GenerateHooksConfig(sirBinaryPath, mode string) ([]byte, error) {
	return json.Marshal(f.GenerateHooksConfigMap(sirBinaryPath, mode))
}
func (f *fakeAgent) DetectInstallation() bool { return true }
func (f *fakeAgent) MinVersion() string       { return "" }
func (f *fakeAgent) GetSpec() *agent.AgentSpec {
	return &f.spec
}
func (f *fakeAgent) GenerateHooksConfigMap(sirBinaryPath, mode string) map[string]interface{} {
	_ = mode
	return map[string]interface{}{
		"customHooks": map[string]interface{}{
			"BeforeTool": []interface{}{
				map[string]interface{}{
					"matcher": ".*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": sirBinaryPath + " guard evaluate --agent fake",
							"timeout": 5,
						},
					},
				},
			},
		},
	}
}

var _ agent.Agent = (*fakeAgent)(nil)
var _ agent.MapBuilder = (*fakeAgent)(nil)

func TestInstallForAgent_CustomManagedKeyRemovesStaleSirEvents(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".sir"), 0o755); err != nil {
		t.Fatal(err)
	}

	ag := newFakeAgent()
	configPath := ag.ConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}

	existing := `{
  "customHooks": {
    "DeprecatedEvent": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "` + sirBinaryPath + ` guard old --agent fake",
            "timeout": 5
          }
        ]
      }
    ],
    "BeforeTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "third-party hook",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "theme": "dark"
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	installForAgent(ag, "guard", tmpHome, true, nil)

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	customHooks := doc["customHooks"].(map[string]interface{})
	if _, ok := customHooks["DeprecatedEvent"]; ok {
		t.Fatalf("stale Sir-managed event was not removed: %+v", customHooks["DeprecatedEvent"])
	}
	beforeTool := customHooks["BeforeTool"].([]interface{})
	if len(beforeTool) != 2 {
		t.Fatalf("expected installed Sir entry plus third-party hook, got %d entries", len(beforeTool))
	}
	first := beforeTool[0].(map[string]interface{})
	inner := first["hooks"].([]interface{})
	cmd := inner[0].(map[string]interface{})["command"].(string)
	if cmd != sirBinaryPath+" guard evaluate --agent fake" {
		t.Fatalf("Sir hook not installed first: %q", cmd)
	}
	if doc["theme"] != "dark" {
		t.Fatalf("theme was not preserved: %#v", doc["theme"])
	}
	if _, err := os.Stat(filepath.Join(tmpHome, ".sir", "hooks-canonical-fake.json")); err != nil {
		t.Fatalf("canonical backup missing: %v", err)
	}
}

func TestInstallForAgent_CustomManagedKeyPreservesNonArrayMetadata(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	if err := os.MkdirAll(filepath.Join(tmpHome, ".sir"), 0o755); err != nil {
		t.Fatal(err)
	}

	ag := newFakeAgent()
	configPath := ag.ConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}

	existing := `{
  "customHooks": {
    "metadata": {
      "managedBy": "upstream",
      "schemaVersion": 2
    },
    "BeforeTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "third-party hook",
            "timeout": 5
          }
        ]
      }
    ]
  }
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	installForAgent(ag, "guard", tmpHome, true, nil)

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	customHooks := doc["customHooks"].(map[string]interface{})
	metadata := customHooks["metadata"].(map[string]interface{})
	if metadata["managedBy"] != "upstream" {
		t.Fatalf("managed subtree metadata was not preserved: %#v", metadata)
	}
	if metadata["schemaVersion"].(float64) != 2 {
		t.Fatalf("managed subtree schemaVersion was not preserved: %#v", metadata)
	}
}

func TestUninstallForAgent_CustomManagedKeyRemovesSirHooks(t *testing.T) {
	tmpHome := t.TempDir()
	t.Setenv("HOME", tmpHome)

	ag := newFakeAgent()
	configPath := ag.ConfigPath()
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}

	existing := `{
  "customHooks": {
    "BeforeTool": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "` + sirBinaryPath + ` guard evaluate --agent fake",
            "timeout": 5
          }
        ]
      },
      {
        "hooks": [
          {
            "type": "command",
            "command": "third-party hook",
            "timeout": 5
          }
        ]
      }
    ]
  },
  "theme": "dark"
}`
	if err := os.WriteFile(configPath, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	if !uninstallForAgent(ag) {
		t.Fatal("uninstallForAgent returned false")
	}

	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	customHooks := doc["customHooks"].(map[string]interface{})
	beforeTool := customHooks["BeforeTool"].([]interface{})
	if len(beforeTool) != 1 {
		t.Fatalf("expected third-party hook only after uninstall, got %d entries", len(beforeTool))
	}
	first := beforeTool[0].(map[string]interface{})
	inner := first["hooks"].([]interface{})
	cmd := inner[0].(map[string]interface{})["command"].(string)
	if cmd != "third-party hook" {
		t.Fatalf("unexpected hook after uninstall: %q", cmd)
	}
	if doc["theme"] != "dark" {
		t.Fatalf("theme was not preserved: %#v", doc["theme"])
	}
}
