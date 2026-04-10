package hooks

import "strings"

// isNetworkCommand checks if a command starts with a network egress tool.
func isNetworkCommand(cmd string) bool {
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

// extractNetworkDest extracts the URL/host from a curl/wget command.
func extractNetworkDest(cmd string) string {
	parts := strings.Fields(cmd)
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if strings.HasPrefix(p, "-") {
			if flagTakesValue(p) && i+1 < len(parts) {
				i++
			}
			continue
		}
		return p
	}
	return ""
}

// isDNSCommand detects DNS exfiltration prefixes (nslookup, dig, host, drill, whois).
func isDNSCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	dnsPrefixes := []string{
		"nslookup ", "dig ", "host ", "drill ",
		"whois ",
	}
	for _, p := range dnsPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return strings.HasPrefix(lower, "hping ") || strings.HasPrefix(lower, "hping3 ")
}

func isPingCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	return strings.HasPrefix(lower, "ping ") || strings.HasPrefix(lower, "ping6 ")
}

// isInterpreterNetworkCommand returns true when a language interpreter is used in one-liner
// mode (-c or -e flag) and the command body contains network API patterns.
func isInterpreterNetworkCommand(cmd string) bool {
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
