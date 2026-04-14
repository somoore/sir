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
	// --no-sandbox is a sir-local flag: consume it from the leading-flags
	// region only (before the wrapped command), NOT from child argv. An
	// attacker who controls an MCP config could otherwise pass
	// `--no-sandbox` after the wrapped command — stripping it globally
	// would silently disable sandbox-exec for their server.
	//
	// The leading-flags region ends at the first token that does not start
	// with `--`. parseMCPProxyInvocation below uses the same convention for
	// --allow-host, so any token after the wrapped command stays untouched
	// and becomes part of that command's argv.
	noSandbox, filtered := stripLeadingNoSandboxFlag(args)

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

// stripLeadingNoSandboxFlag walks args and consumes `--no-sandbox` tokens
// that appear in the leading-flags region only. Tokens after the first
// non-flag token (the wrapped command) are copied verbatim so `--no-sandbox`
// passed as a child-program argument is preserved for that program.
//
// "Leading-flags region" mirrors parseMCPProxyInvocation semantics:
//
//	[--allow-host HOST]... [--no-sandbox]... <command> [args...]
//
// --allow-host and its value are not consumed here — they stay in the
// returned slice for parseMCPProxyInvocation to handle.
func stripLeadingNoSandboxFlag(args []string) (noSandbox bool, rest []string) {
	rest = make([]string, 0, len(args))
	i := 0
	for i < len(args) {
		a := args[i]
		if a == "--no-sandbox" {
			noSandbox = true
			i++
			continue
		}
		if a == "--allow-host" {
			// Pass --allow-host and its argument through untouched;
			// parseMCPProxyInvocation will consume them. We still advance
			// past the value so a subsequent `--no-sandbox` in the leading
			// region is recognized.
			rest = append(rest, a)
			if i+1 < len(args) {
				rest = append(rest, args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}
		// First non-sir-flag token — this is the wrapped command.
		// Copy the remainder verbatim and stop scanning.
		rest = append(rest, args[i:]...)
		return noSandbox, rest
	}
	return noSandbox, rest
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
//  1. --no-sandbox (explicit, user-initiated; only consumed from the sir
//     leading-flags region — see stripLeadingNoSandboxFlag — so child argv
//     cannot inject it from a server's own args)
//  2. Mac-app-helper auto-detect (implicit, path-based). The classifier
//     canonicalizes and symlink-resolves the candidate path before matching,
//     so traversal (`.../MacOS/../../../../bin/sh`) and symlink swaps
//     don't bypass it — see pkg/mcp/macapp.go.
//
// Both fall through to runMCPProxyMonitored, which keeps credential scanning,
// signal forwarding, and process-group cleanup — but drops the network and
// filesystem deny for that server. The user-visible notice is always
// printed; a ledger entry is written best-effort when the current working
// directory hashes to a known sir project (it usually does — MCP clients
// launch helpers from the project directory the developer is working in).
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
//     for credential patterns. A WaitGroup drains the pipe AFTER cmd.Wait()
//     returns and BEFORE runProxyChild returns, avoiding the documented
//     race in os/exec where Wait closes the pipe mid-read. (Wait itself
//     is not gated by the WaitGroup — it waits only on the child process.
//     The WaitGroup just prevents us from exiting while the scan goroutine
//     is still forwarding bytes from the just-closed pipe.)
//  3. The child runs in its own process group so signals addressed to sir
//     don't hit the grandchild twice, and so we can cleanly tear down the
//     whole subtree on shutdown.
//  4. SIGTERM / SIGINT / SIGHUP received by sir are forwarded to the child's
//     process group in a loop for the full lifetime of the child. A second
//     Ctrl-C from the terminal is therefore also forwarded; the loop only
//     exits once cmd.Wait() returns.
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

	// Forward SIGTERM/SIGINT/SIGHUP to the child process group for the
	// full lifetime of the child. Looping (vs. a single select) means a
	// second Ctrl-C from the terminal is also forwarded: graceful shutdown
	// on the first signal, harder kill on the second if the server is
	// stuck. syscall.Kill with a negative PID targets the process group.
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	done := make(chan struct{})
	forwarderDone := make(chan struct{})
	go func() {
		defer close(forwarderDone)
		for {
			select {
			case sig := <-sigCh:
				_ = syscall.Kill(-pgid, sig.(syscall.Signal))
			case <-done:
				return
			}
		}
	}()

	waitErr := cmd.Wait()
	// Stop delivery BEFORE telling the goroutine to exit so no further
	// signals land on sigCh while the goroutine is winding down. Then
	// close(done) lets the goroutine exit and we wait for its drain.
	signal.Stop(sigCh)
	close(done)
	<-forwarderDone

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
// operations not listed are permitted (mach-lookup, signal delivery, etc.)
// but the two categories we care about — outbound network and filesystem
// writes — are constrained.
//
// Network: strict by default. Any --allow-host opts the developer into broad
// outbound access (macOS sandbox-exec cannot express per-host allowlists).
//
// Filesystem writes: denied by default, then re-granted for the minimal set
// of paths an MCP server legitimately needs to function. The allowlist is
// deliberately narrow: each entry is a directory where macOS apps or their
// helper processes are architecturally expected to write (per-app caches,
// prefs, logs, containers) OR a scratch path (temp dirs). Anything broader
// risks creating a persistence or cross-app tampering surface that the
// sandbox was meant to prevent.
//
// What stays denied (notable cases):
//   - ~/.ssh/, ~/.zshrc, ~/.bashrc, ~/.profile — credential and startup files
//   - ~/.config/                                — includes gh/hosts.yml, k8s,
//     fish, etc.; deliberately NOT added to the allowlist even though some
//     legitimate tools would benefit, because this directory is a cross-app
//     auth/persistence surface that we don't want MCP servers writing to
//   - ~/.rustup, ~/.deno, ~/.bun, ~/.pnpm-store, ~/.yarn — toolchain roots
//     where a malicious server could overwrite installers with shims
//   - ~/Library/LaunchAgents, ~/Library/LaunchDaemons — login autostart
//   - ~/Library/Preferences/ByHost and the wider /Library (system-wide)
//   - Anywhere under the user's project directories
//
// What is allowed:
//   - Scratch: /tmp, /private/tmp, /var/folders, /private/var/folders, /dev
//   - Per-app Library subpaths: Application Support, Caches, Preferences
//     (the user-local subtree only), Logs, Containers, Group Containers,
//     Saved Application State, WebKit
//   - The specific dev-tool caches that frequently block normal MCP
//     operation: ~/.npm, ~/.cache, ~/.node_modules, ~/.cargo/registry
//     (note: NOT the whole ~/.cargo — just the registry cache subtree)
//
// Servers that need additional writes should be launched with --no-sandbox
// (documented, ledger-audited) rather than expanded here ad-hoc.
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

	// System scratch — every long-running MCP server needs these for
	// temp files, atomic-rename patterns, and device-node writes.
	for _, p := range []string{"/private/var/folders", "/var/folders", "/private/tmp", "/tmp", "/dev"} {
		fmt.Fprintf(&profile, "(allow file-write* (subpath \"%s\"))\n", p)
	}

	// Per-user application data. The Library/* subpaths cover locations
	// macOS apps and their helper processes are architecturally expected
	// to write to. Everything outside this explicit list stays denied.
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
			".node_modules",
			".cargo/registry",
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
