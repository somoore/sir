package classify

import "strings"

// IsNetworkCommand reports whether cmd starts with a network egress tool.
func IsNetworkCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	prefixes := []string{
		"curl ", "curl\t", "wget ", "wget\t",
		"ssh ", "ssh\t", "scp ", "scp\t", "sftp ", "sftp\t",
		"rsync ", "rsync\t",
		"ftp ", "ftp\t", "ftps ", "lftp ", "ncftp ",
		"nc ", "nc\t", "ncat ", "netcat ", "netcat\t",
		"socat ", "socat\t",
		"telnet ", "telnet\t",
		"openssl s_client",
		"aws s3 cp", "aws s3 sync", "aws s3 mv",
		"gsutil cp", "gsutil rsync", "gsutil mv",
		"az storage blob upload",
		"rclone copy", "rclone sync", "rclone move",
		"s3cmd put", "s3cmd sync",
		"smbclient ",
		"tftp ",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// ExtractNetworkDest extracts the first destination token from curl/wget-like commands.
func ExtractNetworkDest(cmd string) string {
	parts := strings.Fields(cmd)
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if strings.HasPrefix(p, "-") {
			if FlagTakesValue(p) && i+1 < len(parts) {
				i++
			}
			continue
		}
		return p
	}
	return ""
}

// ExtractUnixSocketDestination returns the unix-socket path when the command
// targets one, either via curl's --unix-socket[=]flag, socat's
// UNIX-CONNECT: form, or a unix:// URL. A unix socket is a host-local
// control channel (docker.sock, ssh-agent, dbus) rather than a loopback HTTP
// hop, so callers must not classify it from the URL's hostname alone.
func ExtractUnixSocketDestination(cmd string) (string, bool) {
	parts := strings.Fields(cmd)
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		lower := strings.ToLower(p)
		switch {
		case lower == "--unix-socket" || lower == "-unix-socket":
			if i+1 < len(parts) {
				return parts[i+1], true
			}
		case strings.HasPrefix(lower, "--unix-socket="):
			return p[len("--unix-socket="):], true
		case strings.HasPrefix(lower, "unix://"):
			return p, true
		case strings.HasPrefix(lower, "unix-connect:"):
			return p[len("unix-connect:"):], true
		}
	}
	return "", false
}

// IsDNSCommand detects DNS exfiltration prefixes.
func IsDNSCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range []string{"nslookup ", "dig ", "host ", "drill ", "whois "} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasPrefix(lower, "hping ") || strings.HasPrefix(lower, "hping3 ")
}

// IsPingCommand reports whether cmd is ping or ping6.
func IsPingCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	return strings.HasPrefix(lower, "ping ") || strings.HasPrefix(lower, "ping6 ")
}

// IsInterpreterNetworkCommand returns true for one-liner interpreter network usage.
func IsInterpreterNetworkCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	interpreterPrefixes := []string{
		"python ", "python3 ", "python2 ",
		"node ", "nodejs ",
		"ruby ",
		"perl ",
		"php ",
		"bun ",
		"deno ",
		"go run ",
		"rscript ",
	}

	matchedInterpreter := false
	for _, p := range interpreterPrefixes {
		if strings.HasPrefix(lower, p) {
			matchedInterpreter = true
			break
		}
	}
	if !matchedInterpreter {
		return false
	}

	hasOneLinerFlag := false
	parts := strings.Fields(cmd)
	for _, part := range parts[1:] {
		if part == "-c" || part == "-e" || part == "-r" || part == "--eval" {
			hasOneLinerFlag = true
			break
		}
		if strings.HasPrefix(part, "-") && !strings.HasPrefix(part, "--") && len(part) > 2 {
			if strings.HasSuffix(part, "c") || strings.HasSuffix(part, "e") || strings.HasSuffix(part, "r") {
				hasOneLinerFlag = true
				break
			}
		}
	}
	if !hasOneLinerFlag {
		return false
	}

	networkPatterns := []string{
		"requests.", "urllib", "http.client", "httpx", "aiohttp",
		"socket.connect", "socket.create_connection", "ssl.", "urlopen", "urllib2",
		"fetch(", "http.get", "https.get",
		"require('http", `require("http`, "require('https", `require("https`,
		"axios", "got(", "superagent", "needle",
		"net::http", "open-uri", "uri.open", "faraday", "httparty", "restclient", "tcpsocket",
		"lwp::", "http::", "www::mechanize", "io::socket", "net::http",
		"curl_init", "file_get_contents", "fsockopen", "stream_socket_client",
		".connect(", "socket(", ".send(",
	}

	lowerCmd := strings.ToLower(cmd)
	for _, pattern := range networkPatterns {
		if strings.Contains(lowerCmd, strings.ToLower(pattern)) {
			return true
		}
	}
	return false
}

// IsTestCommand reports whether cmd is a test runner invocation.
func IsTestCommand(cmd string) bool {
	testPrefixes := []string{
		"go test", "npm test", "npm run test", "yarn test",
		"pytest", "python -m pytest", "python3 -m pytest",
		"cargo test", "make test", "bundle exec rspec",
		"jest", "vitest", "mocha",
	}
	lower := strings.ToLower(strings.TrimSpace(cmd))
	for _, p := range testPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
