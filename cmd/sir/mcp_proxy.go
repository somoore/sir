package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/ledger"
	mcppkg "github.com/somoore/sir/pkg/mcp"
	"github.com/somoore/sir/pkg/session"
)

// ---------- sir mcp-proxy ----------

// cmdMCPProxy wraps an MCP server with OS-level hardening and stderr monitoring.
//
// Network: OS-dependent. See RuntimeAssessment() for the effective mode.
// Stderr:  intercepted and scanned for credential patterns. Alerts on detection.
// Files:   write-restricted to temp directories + common app data paths on macOS.
//
// Usage in .mcp.json:
//
//	{
//	  "mcpServers": {
//	    "my-server": {
//	      "command": "/path/to/sir",
//	      "args": ["mcp-proxy", "node", "/path/to/server.js"]
//	    }
//	  }
//	}
//
// For servers that need specific external hosts:
//
//	"args": ["mcp-proxy", "--allow-host", "api.slack.com", "node", "server.js"]
//
// Important: macOS cannot scope egress to specific hosts, so any --allow-host
// broadens to general outbound network access there. Linux network namespaces
// also do not support host-specific exceptions.
func cmdMCPProxy(args []string) {
	// --no-sandbox is a sir-local flag: strip it before handing the rest to
	// the shared mcp-proxy parser, which only knows about --allow-host and
	// the wrapped command. Users opt into monitored mode when the server is
	// a macOS binary that sandbox-exec breaks but our Mac-app-helper
	// heuristic doesn't match (e.g., a helper under ~/bin).
	noSandbox := false
	filtered := make([]string, 0, len(args))
	for _, a := range args {
		if a == "--no-sandbox" {
			noSandbox = true
			continue
		}
		filtered = append(filtered, a)
	}

	allowedHosts, command, cmdArgs, malformed := parseMCPProxyInvocation(filtered)
	if malformed || command == "" {
		fatal("sir mcp-proxy: no command specified after flags")
	}

	proxyOpts := mcpProxyOpts{
		command:      command,
		args:         cmdArgs,
		allowedHosts: allowedHosts,
		noSandbox:    noSandbox,
	}

	var code int
	switch runtime.GOOS {
	case "darwin":
		code = runMCPProxyDarwin(proxyOpts)
	case "linux":
		code = runMCPProxyLinux(proxyOpts)
	default:
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: network sandboxing not available on %s, running with monitoring only\n", runtime.GOOS)
		code = runMCPProxyMonitored(proxyOpts)
	}
	os.Exit(code)
}

type mcpProxyOpts struct {
	command      string
	args         []string
	allowedHosts []string // hosts to allow through the network sandbox
	noSandbox    bool     // --no-sandbox: skip sandbox-exec; keep monitoring
}

// runMCPProxyDarwin uses macOS sandbox-exec to deny outbound network and
// restrict file writes. Stderr is intercepted and scanned for credentials.
//
// Two escape hatches exist before sandbox-exec is attempted:
//
//  1. --no-sandbox (explicit, user-initiated)
//  2. Mac-app-helper auto-detect (implicit, path-based)
//
// Both fall through to runMCPProxyMonitored, which still gives us credential
// scanning + signal forwarding + process-group cleanup — just no network
// or filesystem deny for that server. The user-visible notice and ledger
// entry exist so this degradation is never silent: an attacker cannot slip
// in unsandboxed by controlling a path match, and a developer auditing
// `sir log` always sees which MCP servers ran in which mode.
func runMCPProxyDarwin(opts mcpProxyOpts) int {
	if opts.noSandbox {
		fmt.Fprintf(os.Stderr,
			"sir: mcp-proxy: --no-sandbox requested for %s — running in monitored mode (no network/filesystem isolation; credential scanning and signal forwarding still active)\n",
			opts.command)
		recordMCPProxyDegradation("no_sandbox_flag", opts.command, "--no-sandbox flag supplied")
		return runMCPProxyMonitored(opts)
	}
	if hit, path := mcppkg.IsMacAppHelperCommand(opts.command, opts.args); hit {
		fmt.Fprintf(os.Stderr,
			"sir: mcp-proxy: %s is a macOS .app helper binary — sandbox-exec breaks its XPC handshake to the parent app on this OS. Running in monitored mode (no network/filesystem isolation; credential scanning and signal forwarding still active). Pass --no-sandbox explicitly to silence this notice for other servers.\n",
			path)
		recordMCPProxyDegradation("mac_app_helper", path, "XPC to parent .app blocked under sandbox-exec")
		return runMCPProxyMonitored(opts)
	}

	tmpFile, err := os.CreateTemp("", "sir-sandbox-*.sb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: failed to create sandbox profile: %v\n", err)
		return runMCPProxyMonitored(opts)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(darwinSandboxProfile(opts.allowedHosts)); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: failed to write sandbox profile: %v\n", err)
		tmpFile.Close()
		return runMCPProxyMonitored(opts)
	}
	tmpFile.Close()

	sandboxArgs := []string{"-f", tmpFile.Name(), opts.command}
	sandboxArgs = append(sandboxArgs, opts.args...)

	cmd := exec.Command("sandbox-exec", sandboxArgs...)
	assessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true, AllowedHosts: opts.allowedHosts}, "darwin", true)
	return runProxyChild(cmd, assessment.Summary)
}

// runMCPProxyLinux uses network namespace isolation via unshare.
func runMCPProxyLinux(opts mcpProxyOpts) int {
	if _, err := exec.LookPath("unshare"); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: unshare not found, running with monitoring only\n")
		return runMCPProxyMonitored(opts)
	}

	unshareArgs := []string{"--net", opts.command}
	unshareArgs = append(unshareArgs, opts.args...)

	cmd := exec.Command("unshare", unshareArgs...)
	assessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true, AllowedHosts: opts.allowedHosts}, "linux", true)
	return runProxyChild(cmd, assessment.Summary)
}

// runMCPProxyMonitored runs the MCP server without network sandboxing
// but still scans stderr for credential leakage.
func runMCPProxyMonitored(opts mcpProxyOpts) int {
	cmd := exec.Command(opts.command, opts.args...)
	return runProxyChild(cmd, "")
}

// runProxyChild is the shared execution harness for all three OS paths. It
// owns the stdio plumbing, stderr credential scanning, signal forwarding, and
// process-group management. Every OS-specific runMCPProxy* function must
// delegate here so the reliability properties are identical:
//
//  1. stdout is passed through untouched — MCP JSON-RPC flows through this
//     fd and any buffering or line-splitting would corrupt it.
//  2. stderr is captured via a pipe, teed to the real stderr, and scanned
//     for credential patterns. A WaitGroup gates cmd.Wait() until the scan
//     goroutine has drained the pipe, avoiding the documented race in
//     os/exec where Wait closes the pipe mid-read.
//  3. The child runs in its own process group so signals addressed to sir
//     don't hit the grandchild twice, and so we can cleanly tear down the
//     whole subtree on shutdown.
//  4. SIGTERM / SIGINT / SIGHUP received by sir are forwarded to the child's
//     process group, giving the MCP server a chance to emit a clean JSON-RPC
//     shutdown before exit.
func runProxyChild(cmd *exec.Cmd, assessmentSummary string) int {
	if cmd.Stdin == nil {
		cmd.Stdin = os.Stdin
	}
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}

	// Put the child (and any grandchildren via bash -c, sandbox-exec, etc.)
	// into their own process group. Without this, SIGINT from an interactive
	// terminal goes to every process in the foreground group — sir AND the
	// grandchild get the signal, and the grandchild may die mid-response.
	// With Setpgid, only sir receives the signal, and we forward it down
	// deliberately via signalChildOnce below.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cmd.Stderr = os.Stderr
		stderrPipe = nil
	}

	if assessmentSummary != "" {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %s\n", assessmentSummary)
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		return 1
	}

	// Child is now running in its own PGID (== child PID). Use that as the
	// target for signal forwarding and cleanup.
	pgid := cmd.Process.Pid

	var wg sync.WaitGroup
	if stderrPipe != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanStderrForCredentials(stderrPipe)
		}()
	}

	// Forward SIGTERM/SIGINT/SIGHUP to the child process group. Stop after
	// the first signal — a second Ctrl-C from the terminal, or a follow-up
	// SIGKILL from the launcher, will still land on sir directly because
	// signal.Stop restores default handling.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	done := make(chan struct{})
	go func() {
		select {
		case sig := <-sigCh:
			// syscall.Kill with a negative PID targets the process group.
			_ = syscall.Kill(-pgid, sig.(syscall.Signal))
		case <-done:
		}
	}()

	waitErr := cmd.Wait()
	close(done)
	signal.Stop(sigCh)

	// Drain any remaining stderr before exiting so credentials written just
	// before the child died are still scanned + surfaced.
	wg.Wait()

	// Best-effort cleanup of any orphaned grandchildren left in the group.
	// syscall.Kill returns ESRCH if the group is already empty — that's fine.
	_ = syscall.Kill(-pgid, syscall.SIGTERM)

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", waitErr)
		return 1
	}
	return 0
}

// darwinSandboxProfile returns the sandbox-exec profile text that governs an
// MCP child process. The profile follows a default-allow, explicit-deny model:
// operations not listed are permitted (mach-lookup, kext access, signal
// delivery, etc.) but the two categories we care about — outbound network and
// filesystem writes — are constrained.
//
// Network: strict by default. Any --allow-host opts the developer into broad
// outbound access (macOS sandbox-exec cannot express per-host allowlists).
//
// Filesystem writes: denied by default, then re-granted for the paths an MCP
// server legitimately needs. The allowlist is deliberately broad enough that
// real-world servers (Hopper, language servers, SDK-based tools) work out of
// the box — a narrower list caused cryptic "intermittent stdio" failures when
// a server's first plist/log write returned EPERM mid-JSON-RPC.
//
// What we still deny:
//   - Arbitrary writes under ~/ (the user's home root and non-Library paths)
//   - Anywhere under a project directory the user is currently working in
//   - System paths (/etc, /usr, /Library/ outside of sandbox-provided temp)
//
// This means an exfiltrating server cannot drop payloads into the project,
// cannot write persistent backdoors to ~/.zshrc or ~/Library/LaunchAgents,
// and cannot tamper with cross-app SSH or GPG material — while a legitimate
// server can still cache state, write logs, and update its own prefs.
func darwinSandboxProfile(allowedHosts []string) string {
	var profile strings.Builder
	profile.WriteString("(version 1)\n")
	profile.WriteString("(allow default)\n")

	if len(allowedHosts) > 0 {
		// Developer explicitly granted network access — sandbox still
		// restricts file writes and monitors stderr, but outbound is open.
	} else {
		profile.WriteString("(deny network-outbound)\n")
		profile.WriteString("(allow network-outbound (remote unix-socket))\n")
		profile.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	}

	profile.WriteString("(deny file-write*)\n")

	// System temp directories — every long-running MCP server needs these
	// for scratch files, atomic-rename patterns, and IPC.
	for _, p := range []string{"/private/var/folders", "/var/folders", "/private/tmp", "/tmp", "/dev"} {
		fmt.Fprintf(&profile, "(allow file-write* (subpath \"%s\"))\n", p)
	}

	// Per-user application data. The Library/* subpaths cover the locations
	// macOS apps and their helper processes (Hopper, language servers,
	// SDK-based MCPs) are architecturally expected to write to. Allowing
	// them is what makes sir mcp-proxy "just work" on Darwin.
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		for _, rel := range []string{
			"Library/Application Support",
			"Library/Caches",
			"Library/Preferences",
			"Library/Logs",
			"Library/Containers",
			"Library/Group Containers",
			"Library/Saved Application State",
			"Library/WebKit",
			".npm",
			".cache",
			".config",
			".local/share",
			".local/state",
			".node_modules",
			".cargo/registry",
			".rustup",
			".pnpm-store",
			".yarn",
			".deno",
			".bun",
		} {
			fmt.Fprintf(&profile, "(allow file-write* (subpath \"%s/%s\"))\n", homeDir, rel)
		}
	}
	return profile.String()
}

// recordMCPProxyDegradation appends a ledger entry noting that the proxy ran
// without sandbox-exec. sir mcp-proxy is spawned by the MCP client (Claude
// Code, Gemini, Codex) with no explicit project context, so we use the
// current working directory as a best-effort project key: MCP clients
// typically launch helpers from the project root the developer is working
// in. If cwd doesn't correspond to a known sir project (no session.json
// under ~/.sir/projects/<hash>/), we skip silently — emitting the stderr
// notice is enough for unaudited contexts, and we must never synthesize a
// fresh project directory from a cwd that wasn't a sir project to begin
// with.
func recordMCPProxyDegradation(kind, target, reason string) {
	cwd, err := os.Getwd()
	if err != nil {
		return
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	stateDir := filepath.Join(home, ".sir", "projects", session.ProjectHash(cwd))
	if _, err := os.Stat(filepath.Join(stateDir, "session.json")); err != nil {
		return
	}
	_ = ledger.Append(cwd, &ledger.Entry{
		ToolName:  "mcp-proxy",
		Verb:      "degrade",
		Target:    target,
		Decision:  "allow",
		Reason:    fmt.Sprintf("mcp-proxy running in monitored mode: %s", reason),
		Severity:  "LOW",
		AlertType: "mcp_proxy_degrade_" + kind,
	})
}

// scanStderrForCredentials reads stderr from the MCP server process line by
// line, passes it through to real stderr, and scans each line for credential
// patterns. Alerts if credentials are detected in the server's debug output.
func scanStderrForCredentials(pipe io.ReadCloser) {
	buf := make([]byte, 4096)
	for {
		n, err := pipe.Read(buf)
		if n > 0 {
			chunk := string(buf[:n])
			// Pass through to real stderr
			os.Stderr.WriteString(chunk)
			// Scan for credential patterns
			if found, hint := hooks.ScanStringForCredentials(chunk); found {
				fmt.Fprintf(os.Stderr, "\nsir: mcp-proxy: ALERT — credential pattern detected in server stderr: %s\n", hint)
			}
		}
		if err != nil {
			break
		}
	}
}
