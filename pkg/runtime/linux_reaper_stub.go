//go:build !linux

package runtime

import (
	"os/exec"
	"syscall"
	"time"
)

func enableLinuxContainmentSubreaper() error { return nil }

func reapLinuxContainmentChildren(_ []int, _ time.Duration) error { return nil }

func linuxTerminateAdoptedChildren(time.Duration) error { return nil }

func terminateLinuxContainmentTree(cmd *exec.Cmd, childPID int) {
	if childPID > 0 {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
	}
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.Process.Pid > 0 {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
