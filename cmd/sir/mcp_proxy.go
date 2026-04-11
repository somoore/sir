package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/somoore/sir/pkg/hooks"
)

// ---------- sir mcp-proxy ----------

// cmdMCPProxy wraps an MCP server with OS-level hardening and stderr monitoring.
//
// Network: OS-dependent. See RuntimeAssessment() for the effective mode.
// Stderr:  intercepted and scanned for credential patterns. Alerts on detection.
// Files:   write-restricted to temp directories on macOS only.
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
	allowedHosts, command, cmdArgs, malformed := parseMCPProxyInvocation(args)
	if malformed || command == "" {
		fatal("sir mcp-proxy: no command specified after flags")
	}

	proxyOpts := mcpProxyOpts{
		command:      command,
		args:         cmdArgs,
		allowedHosts: allowedHosts,
	}

	switch runtime.GOOS {
	case "darwin":
		runMCPProxyDarwin(proxyOpts)
	case "linux":
		runMCPProxyLinux(proxyOpts)
	default:
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: network sandboxing not available on %s, running with monitoring only\n", runtime.GOOS)
		runMCPProxyMonitored(proxyOpts)
	}
}

type mcpProxyOpts struct {
	command      string
	args         []string
	allowedHosts []string // hosts to allow through the network sandbox
}

// runMCPProxyDarwin uses macOS sandbox-exec to deny outbound network and
// restrict file writes. Stderr is intercepted and scanned for credentials.
func runMCPProxyDarwin(opts mcpProxyOpts) {
	// Build sandbox profile dynamically.
	// macOS sandbox-exec cannot express per-host allowlists, so this profile
	// either allows only literal loopback endpoints or broad outbound access
	// when the developer has explicitly granted network. Two modes:
	//   - No --allow-host: deny all outbound except localhost
	//   - With --allow-host: allow all outbound (developer explicitly grants network)
	var profile strings.Builder
	profile.WriteString("(version 1)\n")
	profile.WriteString("(allow default)\n")
	if len(opts.allowedHosts) > 0 {
		// Developer explicitly granted network access — allow outbound
		// (sandbox still restricts file writes and monitors stderr)
	} else {
		// Strict mode: deny all outbound except localhost loopback endpoints.
		profile.WriteString("(deny network-outbound)\n")
		profile.WriteString("(allow network-outbound (remote unix-socket))\n")
		profile.WriteString("(allow network-outbound (remote ip \"localhost:*\"))\n")
	}
	// Restrict file writes: only allow OS temp dirs and toolchain caches.
	// MCP servers should NOT be able to write to the user's project directory,
	// home directory, or sir's state directory. This prevents an evil server
	// from writing exfiltrated data to disk for later retrieval.
	profile.WriteString("(deny file-write*)\n")
	profile.WriteString("(allow file-write* (subpath \"/private/var/folders\"))\n") // macOS per-user temp
	profile.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")         // macOS per-user temp
	profile.WriteString("(allow file-write* (subpath \"/dev\"))\n")                 // /dev/null, /dev/tty
	// Allow writing to toolchain caches (node, npm, pip need these)
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		profile.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s/.npm\"))\n", homeDir))
		profile.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s/.cache\"))\n", homeDir))
		profile.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s/Library/Caches\"))\n", homeDir))
		profile.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s/.node_modules\"))\n", homeDir))
	}

	tmpFile, err := os.CreateTemp("", "sir-sandbox-*.sb")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: failed to create sandbox profile: %v\n", err)
		runMCPProxyMonitored(opts)
		return
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(profile.String()); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: failed to write sandbox profile: %v\n", err)
		runMCPProxyMonitored(opts)
		return
	}
	tmpFile.Close()

	sandboxArgs := []string{"-f", tmpFile.Name(), opts.command}
	sandboxArgs = append(sandboxArgs, opts.args...)

	cmd := exec.Command("sandbox-exec", sandboxArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	// Intercept stderr for credential scanning
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cmd.Stderr = os.Stderr // fallback
	}

	assessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true, AllowedHosts: opts.allowedHosts}, "darwin", true)
	fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %s\n", assessment.Summary)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}

	// Scan stderr in background
	if stderrPipe != nil {
		go scanStderrForCredentials(stderrPipe)
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}
}

// runMCPProxyLinux uses network namespace isolation via unshare.
func runMCPProxyLinux(opts mcpProxyOpts) {
	if _, err := exec.LookPath("unshare"); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: unshare not found, running with monitoring only\n")
		runMCPProxyMonitored(opts)
		return
	}

	unshareArgs := []string{"--net", opts.command}
	unshareArgs = append(unshareArgs, opts.args...)

	cmd := exec.Command("unshare", unshareArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cmd.Stderr = os.Stderr
	}

	assessment := assessMCPProxyRuntime(mcpProxySpec{Wrapped: true, AllowedHosts: opts.allowedHosts}, "linux", true)
	fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %s\n", assessment.Summary)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}

	if stderrPipe != nil {
		go scanStderrForCredentials(stderrPipe)
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}
}

// runMCPProxyMonitored runs the MCP server without network sandboxing
// but still scans stderr for credential leakage.
func runMCPProxyMonitored(opts mcpProxyOpts) {
	cmd := exec.Command(opts.command, opts.args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		cmd.Stderr = os.Stderr
	}

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}

	if stderrPipe != nil {
		go scanStderrForCredentials(stderrPipe)
	}

	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "sir: mcp-proxy: %v\n", err)
		os.Exit(1)
	}
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
