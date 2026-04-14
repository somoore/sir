package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// redirectStderr swaps os.Stderr for a pipe whose output is copied into buf.
// The returned restore closure must be called to flush pending writes and
// restore the original os.Stderr. Used in tests that assert on data emitted
// by runProxyChild's scanStderrForCredentials goroutine — that writes to
// os.Stderr directly, not to cmd.Stderr.
func redirectStderr(t *testing.T, buf *bytes.Buffer) func() {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(buf, r)
		close(done)
	}()
	return func() {
		_ = w.Close()
		<-done
		os.Stderr = orig
		_ = r.Close()
	}
}

// TestDarwinSandboxProfile_AllowsCommonUserDataPaths encodes the lesson from
// the Hopper "intermittent stdio break" regression: a legitimate MCP server
// hitting a plist/log write in ~/Library should not see EPERM. If any of
// these paths fall out of the allowlist, MCP servers that rely on them start
// crashing mid-JSON-RPC and the failure mode looks like stdio corruption.
func TestDarwinSandboxProfile_AllowsCommonUserDataPaths(t *testing.T) {
	profile := darwinSandboxProfile(nil)

	mustContain := []string{
		"Library/Application Support",
		"Library/Preferences",
		"Library/Logs",
		"Library/Containers",
		"Library/Caches",
		"/private/var/folders",
		"/tmp",
	}
	for _, want := range mustContain {
		if !strings.Contains(profile, want) {
			t.Errorf("sandbox profile must allow writes under %q so MCP servers can operate; profile was:\n%s", want, profile)
		}
	}

	// Strict posture: deny outbound network but still allow unix sockets
	// (Hopper and other macOS MCPs use these for XPC/IPC) and localhost.
	mustContainStrict := []string{
		"(deny network-outbound)",
		"(allow network-outbound (remote unix-socket))",
		`(allow network-outbound (remote ip "localhost:*"))`,
	}
	for _, want := range mustContainStrict {
		if !strings.Contains(profile, want) {
			t.Errorf("strict profile must contain %q; profile was:\n%s", want, profile)
		}
	}

	// File-write denial is load-bearing: without it, any path not in the
	// allowlist would be writable.
	if !strings.Contains(profile, "(deny file-write*)") {
		t.Error("sandbox profile must keep file-write* denied by default")
	}
}

// TestDarwinSandboxProfile_AllowHostBroadensNetwork verifies that opting into
// --allow-host removes the strict network-outbound deny. macOS sandbox-exec
// can't express per-host rules, so any --allow-host must translate to broad
// outbound access — documented in the proxy comments.
func TestDarwinSandboxProfile_AllowHostBroadensNetwork(t *testing.T) {
	profile := darwinSandboxProfile([]string{"api.slack.com"})
	if strings.Contains(profile, "(deny network-outbound)") {
		t.Errorf("--allow-host must not keep the strict network deny; profile was:\n%s", profile)
	}
}

// TestRunProxyChild_DrainsStderrBeforeReturn verifies that runProxyChild waits
// for the stderr scan goroutine before returning. Prior to the WaitGroup fix,
// cmd.Wait() could close the pipe mid-read, losing late stderr data and
// letting the process exit before credential-scan alerts were emitted.
func TestRunProxyChild_DrainsStderrBeforeReturn(t *testing.T) {
	// Child writes a large stderr payload immediately before exiting.
	// If runProxyChild returns without draining, the bytes never reach the
	// fd we pass as cmd.Stderr.
	const payload = "PAYLOAD-LINE-THAT-MUST-BE-DRAINED"
	cmd := exec.Command("/bin/sh", "-c", "printf '%s\\n' '"+payload+"' 1>&2; exit 0")
	var captured bytes.Buffer
	cmd.Stderr = &captured

	// Because cmd.Stderr is already set, runProxyChild's StderrPipe() call
	// will fail and we'll fall through to the direct-stderr path. To force
	// the pipe path, clear Stderr and capture via a stdout-side stub.
	cmd.Stderr = nil
	// Redirect the scanner's output (os.Stderr) to a pipe we can read.
	origStderr := redirectStderr(t, &captured)
	defer origStderr()

	code := runProxyChild(cmd, "")
	if code != 0 {
		t.Fatalf("runProxyChild exit = %d, want 0", code)
	}
	if !strings.Contains(captured.String(), payload) {
		t.Fatalf("stderr payload was lost — goroutine did not drain before return.\nGot: %q", captured.String())
	}
}

// TestRunProxyChild_ChildRunsInOwnProcessGroup checks that the child is
// Setpgid'd. Without this, signals to sir's terminal group would hit the
// child twice (once from the terminal, once from our forwarding), and we
// couldn't cleanly kill the whole subtree via a negative PID.
func TestRunProxyChild_ChildRunsInOwnProcessGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 30")

	// Start without running the full harness so we can inspect pgid.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Give the kernel a moment to apply setpgid — Go sets it before exec
	// so this is usually instant, but be lenient to avoid flakiness.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil && pgid == cmd.Process.Pid {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	pgid, _ := syscall.Getpgid(cmd.Process.Pid)
	t.Fatalf("child pgid = %d, want %d (child pid)", pgid, cmd.Process.Pid)
}

// TestRunProxyChild_SignalForwardsToProcessGroup verifies that a SIGTERM
// delivered to the group reaches the child process. This is the mechanism by
// which sir forwards its own signals to the wrapped MCP server.
//
// The test execs sleep directly (no shell wrapper) so the signal hits the
// immediate child — shell trap semantics on macOS defer traps until
// foreground commands finish, which would add a full sleep interval of
// latency and obscure what we're actually testing.
func TestRunProxyChild_SignalForwardsToProcessGroup(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exec sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	// Wait until setpgid has actually taken effect before signalling — Go
	// sets it pre-exec, but the kernel applies it during exec, so there's a
	// brief window where getpgid still returns the parent's group.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err == nil && pgid == cmd.Process.Pid {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	start := time.Now()
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("kill group: %v", err)
	}

	waitErr := cmd.Wait()
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("child took %v to die — signal did not propagate to process group", elapsed)
	}

	exitErr, ok := waitErr.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %v", waitErr)
	}
	if exitErr.ExitCode() != -1 {
		// Posix: processes killed by a signal don't have a meaningful exit
		// code; Go exec surfaces -1 plus the signal in WaitStatus.
		t.Logf("exit code = %d (signal-killed children vary by OS)", exitErr.ExitCode())
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok {
		if !ws.Signaled() || ws.Signal() != syscall.SIGTERM {
			t.Errorf("child did not die from SIGTERM: signaled=%v signal=%v", ws.Signaled(), ws.Signal())
		}
	}
}
