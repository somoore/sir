//go:build linux

package runtime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const linuxPrSetChildSubreaper = 36

var linuxProcRoot = "/proc"

func enableLinuxContainmentSubreaper() error {
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, uintptr(linuxPrSetChildSubreaper), uintptr(1), 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func terminateLinuxContainmentTree(cmd *exec.Cmd, childPID int) {
	_ = enableLinuxContainmentSubreaper()

	descendants := linuxContainmentDescendantPIDs(cmd, childPID)
	for i := len(descendants) - 1; i >= 0; i-- {
		_ = syscall.Kill(descendants[i], syscall.SIGKILL)
	}

	if cmd == nil || cmd.Process == nil {
		_ = linuxTerminateAdoptedChildren(2 * time.Second)
		return
	}
	if cmd.Process.Pid > 0 {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = syscall.Kill(cmd.Process.Pid, syscall.SIGKILL)
	}
	_, _ = cmd.Process.Wait()
	_ = reapLinuxContainmentChildren(descendants, 2*time.Second)
	_ = linuxTerminateAdoptedChildren(2 * time.Second)
}

func linuxContainmentDescendantPIDs(cmd *exec.Cmd, childPID int) []int {
	seen := make(map[int]struct{})
	var descendants []int
	add := func(pid int) {
		if pid <= 0 {
			return
		}
		if _, ok := seen[pid]; ok {
			return
		}
		seen[pid] = struct{}{}
		descendants = append(descendants, pid)
	}

	if childPID > 0 {
		add(childPID)
	}
	if cmd != nil && cmd.Process != nil && cmd.Process.Pid > 0 {
		for _, pid := range linuxDescendantPIDs(cmd.Process.Pid) {
			add(pid)
		}
	}
	return descendants
}

func linuxDescendantPIDs(rootPID int) []int {
	if rootPID <= 0 {
		return nil
	}
	queue := []int{rootPID}
	seen := map[int]struct{}{rootPID: {}}
	var descendants []int
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		children, err := linuxChildPIDs(pid)
		if err != nil {
			continue
		}
		for _, child := range children {
			if _, ok := seen[child]; ok {
				continue
			}
			seen[child] = struct{}{}
			descendants = append(descendants, child)
			queue = append(queue, child)
		}
	}
	return descendants
}

func linuxChildPIDs(pid int) ([]int, error) {
	taskRoot := filepath.Join(linuxProcRoot, strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskRoot)
	if err != nil {
		return nil, err
	}

	seen := make(map[int]struct{})
	var out []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		raw, err := os.ReadFile(filepath.Join(taskRoot, entry.Name(), "children"))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}

		fields := strings.Fields(string(raw))
		for _, field := range fields {
			childPID, err := strconv.Atoi(field)
			if err != nil {
				return nil, fmt.Errorf("parse child pid %q: %w", field, err)
			}
			if childPID <= 0 {
				continue
			}
			if _, ok := seen[childPID]; ok {
				continue
			}
			seen[childPID] = struct{}{}
			out = append(out, childPID)
		}
	}
	slices.Sort(out)
	return out, nil
}

func reapLinuxContainmentChildren(pids []int, timeout time.Duration) error {
	if len(pids) == 0 {
		return reapLinuxKnownChildren(timeout)
	}

	remaining := make([]int, 0, len(pids))
	seen := make(map[int]struct{}, len(pids))
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		if _, ok := seen[pid]; ok {
			continue
		}
		seen[pid] = struct{}{}
		remaining = append(remaining, pid)
	}

	deadline := time.Now().Add(timeout)
	for len(remaining) > 0 {
		next := remaining[:0]
		for _, pid := range remaining {
			reaped, err := linuxReapOrCheckPID(pid)
			if err != nil {
				return err
			}
			if !reaped {
				next = append(next, pid)
			}
		}
		remaining = next
		if len(remaining) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			slices.Sort(remaining)
			return fmt.Errorf("timed out waiting for containment descendants: %v", remaining)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

func linuxTerminateAdoptedChildren(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	quietRounds := 0
	for {
		_ = reapLinuxKnownChildren(50 * time.Millisecond)

		children, err := linuxChildPIDs(os.Getpid())
		if err != nil {
			return err
		}
		if len(children) == 0 {
			quietRounds++
			if quietRounds >= 5 {
				_ = reapLinuxKnownChildren(50 * time.Millisecond)
				return nil
			}
			time.Sleep(20 * time.Millisecond)
			continue
		}

		quietRounds = 0
		for _, pid := range children {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
		if time.Now().After(deadline) {
			_ = reapLinuxKnownChildren(50 * time.Millisecond)
			return fmt.Errorf("timed out waiting for adopted containment children")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func reapLinuxKnownChildren(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
		switch {
		case pid > 0:
			continue
		case err == nil:
			if time.Now().After(deadline) {
				return nil
			}
			time.Sleep(10 * time.Millisecond)
		case err == syscall.ECHILD:
			return nil
		case err == syscall.EINTR:
			continue
		default:
			return err
		}
	}
}

func linuxReapOrCheckPID(pid int) (bool, error) {
	var status syscall.WaitStatus
	reapedPID, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
	switch {
	case reapedPID == pid:
		return true, nil
	case err == nil:
		if sigErr := syscall.Kill(pid, syscall.Signal(0)); sigErr == syscall.ESRCH {
			return true, nil
		} else if sigErr != nil {
			return false, sigErr
		}
		return false, nil
	case err == syscall.ECHILD:
		if sigErr := syscall.Kill(pid, syscall.Signal(0)); sigErr == syscall.ESRCH {
			return true, nil
		} else if sigErr != nil {
			return false, sigErr
		}
		return false, nil
	case err == syscall.EINTR:
		return false, nil
	default:
		return false, err
	}
}
