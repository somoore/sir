// install_test.go — Smoke test for sir install producing valid hooks config.
package tests

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesValidHooks(t *testing.T) {
	// Use a temp HOME so we don't clobber real settings
	tmpHome := t.TempDir()
	projectRoot := t.TempDir()
	geminiPath := filepath.Join(tmpHome, ".gemini", "settings.json")
	if err := os.MkdirAll(filepath.Dir(geminiPath), 0o755); err != nil {
		t.Fatalf("mkdir .gemini: %v", err)
	}
	if err := os.WriteFile(geminiPath, []byte(`{}`), 0o644); err != nil {
		t.Fatalf("seed Gemini settings.json: %v", err)
	}

	// Build sir binary
	sirBin := filepath.Join(t.TempDir(), "sir")
	buildCmd := exec.Command("go", "build", "-o", sirBin, "./cmd/sir")
	buildCmd.Dir = findRepoRoot(t)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("build sir: %v\n%s", err, out)
	}

	// Run sir install --yes with fake HOME
	installCmd := exec.Command(sirBin, "install", "--yes")
	installCmd.Dir = projectRoot
	installCmd.Env = append(os.Environ(), "HOME="+tmpHome)
	if out, err := installCmd.CombinedOutput(); err != nil {
		t.Fatalf("sir install: %v\n%s", err, out)
	}

	// Read the generated Gemini config. Default install should auto-detect the
	// supported agents already present instead of manufacturing a Claude-only
	// config on a machine that only has Gemini signals.
	data, err := os.ReadFile(geminiPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatalf("parse settings.json: %v\n%s", err, data)
	}

	hooks, ok := config["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks is not a map: %T", config["hooks"])
	}

	// Verify BeforeTool is non-null array
	pre, ok := hooks["BeforeTool"].([]interface{})
	if !ok || pre == nil {
		t.Fatalf("BeforeTool is null or not an array: %v", hooks["BeforeTool"])
	}
	if len(pre) == 0 {
		t.Fatal("BeforeTool is empty")
	}

	// Verify AfterTool is non-null array
	post, ok := hooks["AfterTool"].([]interface{})
	if !ok || post == nil {
		t.Fatalf("AfterTool is null or not an array: %v", hooks["AfterTool"])
	}
	if len(post) == 0 {
		t.Fatal("AfterTool is empty")
	}

	// Verify sir guard commands are present
	foundPre := false
	foundPost := false
	rawJSON := string(data)
	if strings.Contains(rawJSON, "sir guard evaluate") {
		foundPre = true
	}
	if strings.Contains(rawJSON, "sir guard post-evaluate") {
		foundPost = true
	}
	if !foundPre {
		t.Error("sir guard evaluate not found in settings.json")
	}
	if !foundPost {
		t.Error("sir guard post-evaluate not found in settings.json")
	}

	// Run sir status with same HOME — should report installed
	statusCmd := exec.Command(sirBin, "status")
	statusCmd.Dir = projectRoot
	statusCmd.Env = append(os.Environ(), "HOME="+tmpHome)
	statusOut, err := statusCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sir status: %v\n%s", err, statusOut)
	}
	if strings.Contains(string(statusOut), "NOT INSTALLED") {
		t.Errorf("sir status says NOT INSTALLED after install:\n%s", statusOut)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repo root (no go.mod found)")
		}
		dir = parent
	}
}
