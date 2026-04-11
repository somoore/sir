//go:build linux

package runtime

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestLinuxChildPIDsReadsAllTaskChildren(t *testing.T) {
	procRoot := t.TempDir()
	makeTaskChildren := func(taskID string, content string) {
		path := filepath.Join(procRoot, "123", "task", taskID)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatalf("mkdir task dir %s: %v", taskID, err)
		}
		if err := os.WriteFile(filepath.Join(path, "children"), []byte(content), 0o600); err != nil {
			t.Fatalf("write task %s children: %v", taskID, err)
		}
	}

	makeTaskChildren("123", "11 12\n")
	makeTaskChildren("456", "12 13\n")

	originalProcRoot := linuxProcRoot
	linuxProcRoot = procRoot
	t.Cleanup(func() {
		linuxProcRoot = originalProcRoot
	})

	children, err := linuxChildPIDs(123)
	if err != nil {
		t.Fatalf("linuxChildPIDs: %v", err)
	}
	if !slices.Equal([]int{11, 12, 13}, children) {
		t.Fatalf("linuxChildPIDs = %v, want [11 12 13]", children)
	}
}
