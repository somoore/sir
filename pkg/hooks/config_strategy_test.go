package hooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractManagedSubtree_CustomKey(t *testing.T) {
	raw := []byte(`{"customHooks":{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]},"theme":"dark"}`)

	got, err := ExtractManagedSubtree(raw, "customHooks")
	if err != nil {
		t.Fatalf("ExtractManagedSubtree: %v", err)
	}

	want := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]}`)
	if !jsonEqual(t, got, want) {
		t.Fatalf("managed subtree mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestAutoRestoreAgentHookFile_CustomSubtreeKey(t *testing.T) {
	tmpDir := t.TempDir()
	livePath := filepath.Join(tmpDir, "settings.json")
	canonicalPath := filepath.Join(tmpDir, "canonical.json")

	live := []byte(`{"customHooks":{"BeforeTool":[{"hooks":[{"command":"tampered"}]}]},"theme":"dark","mcpServers":{"ok":{"command":"demo"}}}`)
	canonical := []byte(`{"BeforeTool":[{"hooks":[{"command":"sir guard evaluate"}]}]}`)

	if err := os.WriteFile(livePath, live, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(canonicalPath, canonical, 0o600); err != nil {
		t.Fatal(err)
	}

	f := AgentHookFile{
		DisplayPath:   "~/custom/settings.json",
		AbsPath:       livePath,
		CanonicalPath: canonicalPath,
		AgentName:     "Custom Agent",
		SubtreeKey:    "customHooks",
	}
	if !AutoRestoreAgentHookFile(f) {
		t.Fatal("AutoRestoreAgentHookFile returned false")
	}

	restored, err := os.ReadFile(livePath)
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(restored, &doc); err != nil {
		t.Fatalf("unmarshal restored config: %v", err)
	}

	gotHooks, err := json.Marshal(doc["customHooks"])
	if err != nil {
		t.Fatalf("marshal customHooks: %v", err)
	}
	if !jsonEqual(t, gotHooks, canonical) {
		t.Fatalf("customHooks subtree not restored:\n got: %s\nwant: %s", gotHooks, canonical)
	}
	if doc["theme"] != "dark" {
		t.Fatalf("theme was not preserved: %#v", doc["theme"])
	}
	if _, ok := doc["mcpServers"].(map[string]interface{}); !ok {
		t.Fatalf("mcpServers was not preserved: %#v", doc["mcpServers"])
	}
}
