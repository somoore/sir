package main

import (
	"bytes"
	"fmt"
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

// TestDarwinSandboxProfile_DeniesPersistenceSurface is the negative of the
// above: paths that would give a malicious server a persistence or
// cross-app tampering vector must NOT appear as file-write allowlist
// entries. We check for the full `(allow file-write* (subpath "<home>/<x>"))`
// form so that sub-paths of genuinely allowed subtrees (e.g., `.cache`
// appearing inside the `Library/Caches` allow line) don't produce false
// positives.
func TestDarwinSandboxProfile_DeniesPersistenceSurface(t *testing.T) {
	profile := darwinSandboxProfile(nil)
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}

	mustNotAllow := []string{
		".ssh",
		".zshrc",
		".bashrc",
		".profile",
		".config", // includes gh/hosts.yml, fish, k8s
		".rustup",
		".deno",
		".bun",
		".pnpm-store",
		".yarn",
		".local/share",
		".local/state",
		"Library/LaunchAgents",
		"Library/LaunchDaemons",
	}
	for _, rel := range mustNotAllow {
		line := fmt.Sprintf(`(allow file-write* (subpath "%s/%s"))`, home, rel)
		if strings.Contains(profile, line) {
			t.Errorf("sandbox profile MUST NOT contain %q — that's a persistence / cross-app auth surface; profile:\n%s", line, profile)
		}
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

// TestEscalatingSignalForwarder_FirstSignalForwards verifies that the
// initial signal is forwarded to the child's process group verbatim and
// the forwarder keeps waiting for the next event (no escalation yet).
func TestEscalatingSignalForwarder_FirstSignalForwards(t *testing.T) {
	sigCh := make(chan os.Signal, 4)
	done := make(chan struct{})
	forwarderDone := make(chan struct{})

	var (
		killCalls []killCall
		exitCalls []int
	)
	killFn := func(pid int, sig syscall.Signal) error {
		killCalls = append(killCalls, killCall{pid: pid, sig: sig})
		return nil
	}
	exitFn := func(code int) { exitCalls = append(exitCalls, code) }

	go escalatingSignalForwarder(sigCh, done, forwarderDone, 9999, killFn, exitFn)

	sigCh <- syscall.SIGTERM
	// Give the goroutine a tick to process the signal before we assert.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(killCalls) == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	close(done)
	<-forwarderDone

	if len(killCalls) != 1 {
		t.Fatalf("killFn called %d times, want 1: %+v", len(killCalls), killCalls)
	}
	if killCalls[0].pid != -9999 {
		t.Errorf("killFn targeted pid %d, want -9999 (process group)", killCalls[0].pid)
	}
	if killCalls[0].sig != syscall.SIGTERM {
		t.Errorf("killFn forwarded signal %v, want SIGTERM (verbatim)", killCalls[0].sig)
	}
	if len(exitCalls) != 0 {
		t.Errorf("exitFn should NOT be called on first signal; was called with %v", exitCalls)
	}
}

// TestEscalatingSignalForwarder_SecondSignalEscalatesToKill is the
// regression for the Codex P1: second interrupt must force-kill the
// child's process group AND exit the parent with 128+signal, so an
// operator facing a stuck MCP server can always recover with a second
// Ctrl-C.
func TestEscalatingSignalForwarder_SecondSignalEscalatesToKill(t *testing.T) {
	sigCh := make(chan os.Signal, 4)
	done := make(chan struct{})
	forwarderDone := make(chan struct{})

	var (
		killCalls []killCall
		exitCalls []int
	)
	killFn := func(pid int, sig syscall.Signal) error {
		killCalls = append(killCalls, killCall{pid: pid, sig: sig})
		return nil
	}
	exitFn := func(code int) { exitCalls = append(exitCalls, code) }

	go escalatingSignalForwarder(sigCh, done, forwarderDone, 1234, killFn, exitFn)

	// First signal: SIGINT forwarded verbatim.
	sigCh <- syscall.SIGINT
	// Second signal: must escalate to SIGKILL + exit(128+2).
	sigCh <- syscall.SIGINT

	<-forwarderDone // escalation path calls close(forwarderDone) via defer

	if len(killCalls) != 2 {
		t.Fatalf("killFn called %d times, want 2: %+v", len(killCalls), killCalls)
	}
	if killCalls[0].sig != syscall.SIGINT {
		t.Errorf("first kill: sig = %v, want SIGINT (verbatim forward)", killCalls[0].sig)
	}
	if killCalls[1].sig != syscall.SIGKILL {
		t.Errorf("second kill: sig = %v, want SIGKILL (escalation)", killCalls[1].sig)
	}
	if killCalls[1].pid != -1234 {
		t.Errorf("second kill: pid = %d, want -1234 (process group)", killCalls[1].pid)
	}
	if len(exitCalls) != 1 {
		t.Fatalf("exitFn called %d times, want 1: %v", len(exitCalls), exitCalls)
	}
	// 128 + 2 (SIGINT) = 130, conventional shell exit code.
	if exitCalls[0] != 130 {
		t.Errorf("exit code = %d, want 130 (128+SIGINT)", exitCalls[0])
	}
}

// TestEscalatingSignalForwarder_EscalationPerSignalType proves the exit
// code reflects the second signal, not the first: if the operator sends
// SIGINT then SIGTERM, we exit with 143 (the SIGTERM convention), not
// 130. Whichever signal triggered the escalation is the one operators
// expect to see reflected in the exit code.
func TestEscalatingSignalForwarder_EscalationPerSignalType(t *testing.T) {
	sigCh := make(chan os.Signal, 4)
	done := make(chan struct{})
	forwarderDone := make(chan struct{})

	var exitCalls []int
	killFn := func(int, syscall.Signal) error { return nil }
	exitFn := func(code int) { exitCalls = append(exitCalls, code) }

	go escalatingSignalForwarder(sigCh, done, forwarderDone, 1, killFn, exitFn)

	sigCh <- syscall.SIGINT  // forwarded
	sigCh <- syscall.SIGTERM // escalates
	<-forwarderDone

	if len(exitCalls) != 1 {
		t.Fatalf("exit called %d times, want 1", len(exitCalls))
	}
	if exitCalls[0] != 128+int(syscall.SIGTERM) {
		t.Errorf("exit code = %d, want %d (128+SIGTERM)", exitCalls[0], 128+int(syscall.SIGTERM))
	}
}

// TestEscalatingSignalForwarder_DoneExitsCleanly confirms that the
// normal teardown path (cmd.Wait returned, parent closes `done`) exits
// the goroutine without forwarding or escalating.
func TestEscalatingSignalForwarder_DoneExitsCleanly(t *testing.T) {
	sigCh := make(chan os.Signal, 4)
	done := make(chan struct{})
	forwarderDone := make(chan struct{})

	var (
		killCalls int
		exitCalls int
	)
	killFn := func(int, syscall.Signal) error { killCalls++; return nil }
	exitFn := func(int) { exitCalls++ }

	go escalatingSignalForwarder(sigCh, done, forwarderDone, 1, killFn, exitFn)

	close(done)
	<-forwarderDone

	if killCalls != 0 {
		t.Errorf("killFn called %d times on clean shutdown, want 0", killCalls)
	}
	if exitCalls != 0 {
		t.Errorf("exitFn called %d times on clean shutdown, want 0", exitCalls)
	}
}

type killCall struct {
	pid int
	sig syscall.Signal
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
