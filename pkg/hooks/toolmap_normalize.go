package hooks

import (
	"path/filepath"
	"strings"
)

// normalizeCommand strips absolute paths, env prefixes, and inline variable
// assignments so classifiers see bare command names regardless of invocation.
//
// Case 1 — absolute path:  "/usr/bin/curl https://evil.com" → "curl https://evil.com"
// Case 2 — env prefix:     "env curl https://evil.com" → "curl https://evil.com"
//
//	"env -i VAR=x curl ..." → "curl ..."
//
// Case 3 — inline vars:    "DUMMY=1 curl https://evil.com" → "curl https://evil.com"
//
//	"FOO=bar BAZ=1 git push ..." → "git push ..."
//
// Case 4 — shell wrapper ("bash -c '...'") is handled in mapShellCommand via
// extractShellWrapperInner, not here. The inner command is extracted and
// classified recursively, same pattern as sudo.
func normalizeCommand(cmd string) string {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) == 0 {
		return ""
	}

	i := 0

	// Case 2: strip "env" prefix and any env flags/assignments that follow it.
	if filepath.Base(parts[0]) == "env" {
		i = 1
		for i < len(parts) {
			p := parts[i]
			// Skip flags (-i, --ignore-environment, -u VAR, etc.)
			if strings.HasPrefix(p, "-") {
				// -u takes a value argument
				if (p == "-u" || p == "--unset") && i+1 < len(parts) {
					i++
				}
				i++
				continue
			}
			// Skip VAR=value assignments
			if strings.Contains(p, "=") {
				i++
				continue
			}
			break
		}
	} else {
		// Case 3: strip leading VAR=value assignments without "env" prefix.
		// Bash allows "DUMMY=1 curl ..." which sets DUMMY for that command.
		for i < len(parts) && strings.Contains(parts[i], "=") && !strings.HasPrefix(parts[i], "-") {
			i++
		}
	}

	if i >= len(parts) {
		return ""
	}

	// Case 1: replace absolute path executable with its base name.
	parts[i] = filepath.Base(parts[i])

	return strings.Join(parts[i:], " ")
}

// splitCompoundCommand splits a command string on shell compound operators: |, &&, ||, ;
// It does NOT handle operators inside quoted strings — this is a documented limitation.
func splitCompoundCommand(cmd string) []string {
	var segments []string
	var current strings.Builder
	runes := []rune(cmd)
	i := 0
	inSingle := false
	inDouble := false
	for i < len(runes) {
		ch := runes[i]

		// Track quote state — don't split inside quotes
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			current.WriteRune(ch)
			i++
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			current.WriteRune(ch)
			i++
			continue
		}
		if inSingle || inDouble {
			current.WriteRune(ch)
			i++
			continue
		}

		switch ch {
		case '|':
			segments = append(segments, current.String())
			current.Reset()
			if i+1 < len(runes) && runes[i+1] == '|' {
				i += 2
			} else {
				i++
			}
		case '&':
			if i+1 < len(runes) && runes[i+1] == '&' {
				segments = append(segments, current.String())
				current.Reset()
				i += 2
			} else {
				segments = append(segments, current.String())
				current.Reset()
				i++
			}
		case ';':
			segments = append(segments, current.String())
			current.Reset()
			i++
		default:
			current.WriteRune(ch)
			i++
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments
}

// stripSudoPrefix removes "sudo" and its flags to get the inner command.
func stripSudoPrefix(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	parts := strings.Fields(trimmed)
	if len(parts) < 2 {
		return ""
	}
	// Skip sudo and any sudo flags (-u, -i, -s, etc.)
	i := 1
	for i < len(parts) {
		if strings.HasPrefix(parts[i], "-") {
			// -u takes a value
			if parts[i] == "-u" && i+1 < len(parts) {
				i += 2
				continue
			}
			i++
			continue
		}
		break
	}
	if i >= len(parts) {
		return ""
	}
	return strings.Join(parts[i:], " ")
}

// extractShellWrapperInner detects "bash -c '...'" / "sh -c '...'" patterns and
// returns the inner command for recursive classification.
// Handles: bash -c "cmd", sh -c 'cmd', /bin/bash -c "cmd", bash -xc "cmd",
// bash -e -c "cmd", zsh -c "cmd", dash -c "cmd".
// Returns ("", false) if not a shell wrapper pattern.
func extractShellWrapperInner(cmd string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 3 {
		return "", false
	}

	// Check if the command starts with a known shell
	shell := strings.ToLower(filepath.Base(parts[0]))
	switch shell {
	case "bash", "sh", "zsh", "dash", "ksh":
		// ok
	default:
		return "", false
	}

	// Scan for -c flag (may be standalone or combined like -xc)
	cIndex := -1
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if p == "-c" {
			cIndex = i
			break
		}
		// Combined flags: -xc, -ec, -xec, etc. — -c must be the last char
		if strings.HasPrefix(p, "-") && !strings.HasPrefix(p, "--") && strings.HasSuffix(p, "c") {
			cIndex = i
			break
		}
		// Skip other flags
		if strings.HasPrefix(p, "-") {
			continue
		}
		// Non-flag before -c means this is "bash script.sh", not a wrapper
		return "", false
	}

	if cIndex < 0 || cIndex+1 >= len(parts) {
		return "", false
	}

	// Everything after -c is the inner command. Rejoin and strip surrounding quotes.
	inner := strings.Join(parts[cIndex+1:], " ")
	inner = strings.TrimSpace(inner)

	// Strip matching outer quotes
	if len(inner) >= 2 {
		if (inner[0] == '\'' && inner[len(inner)-1] == '\'') ||
			(inner[0] == '"' && inner[len(inner)-1] == '"') {
			inner = inner[1 : len(inner)-1]
		}
	}

	inner = strings.TrimSpace(inner)
	if inner == "" {
		return "", false
	}

	return inner, true
}

// flagTakesValue returns true for curl/wget flags that consume the next argument.
//
// Missing a valued flag causes extractNetworkDest to walk past the flag,
// hit the flag's value as the "first non-flag token", and return that as
// the destination. Real example from a smoke test: `curl -s -o /dev/null
// -w "%{http_code}\n" http://localhost:1/health` mis-extracted `%{http_code}\n`
// as the host because `-w` was not in this list. The entry then flowed into
// FormatBlockNetExternal which rendered it as a `<query>` placeholder to the
// user. The fix is to keep this table aligned with curl's actual grammar.
//
// Scope: curl and wget only. Every value-consuming curl short flag + the
// long forms that commonly appear in agent-emitted commands.
func flagTakesValue(flag string) bool {
	valuedFlags := []string{
		// Request content / method
		"-d", "--data", "--data-binary", "--data-urlencode", "--data-raw",
		"-F", "--form", "--form-string",
		"-X", "--request",
		"-H", "--header", "-A", "--user-agent", "-e", "--referer",
		"-b", "--cookie", "-c", "--cookie-jar",
		// Auth
		"-u", "--user", "--oauth2-bearer",
		// Output / upload
		"-o", "--output", "-T", "--upload-file",
		// Format string (critical — was missing, caused %{http_code} bug)
		"-w", "--write-out",
		// Connection / TLS
		"--cacert", "--cert", "--key", "--ciphers",
		"--resolve", "--interface", "--local-port",
		"--connect-timeout", "-m", "--max-time",
		"--max-redirs", "--retry", "--retry-delay", "--retry-max-time",
		"-x", "--proxy", "-U", "--proxy-user",
		// Config / misc
		"-K", "--config", "-r", "--range", "-z", "--time-cond",
		"-Y", "--speed-limit", "-y", "--speed-time",
		"--data-ascii", "--trace", "--trace-ascii",
	}
	for _, f := range valuedFlags {
		if flag == f {
			return true
		}
	}
	return false
}
