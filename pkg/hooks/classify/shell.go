package classify

import (
	"path/filepath"
	"strings"
)

// NormalizeCommand strips absolute paths, env prefixes, and inline variable
// assignments so classifiers see bare command names regardless of invocation.
//
// Newlines are preserved as segment boundaries. Flattening them to spaces
// (the old behaviour) let a multi-line Bash command be classified by its
// first line only: "echo hi\ncurl https://evil" looked like `echo`. The
// shell executes each line, so each line is normalized independently.
func NormalizeCommand(cmd string) string {
	cmd = strings.ReplaceAll(cmd, "\r\n", "\n")
	cmd = strings.ReplaceAll(cmd, "\r", "\n")
	if !strings.Contains(cmd, "\n") {
		return normalizeCommandLine(cmd)
	}
	lines := strings.Split(cmd, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if normalized := normalizeCommandLine(line); normalized != "" {
			out = append(out, normalized)
		}
	}
	return strings.Join(out, "\n")
}

func normalizeCommandLine(cmd string) string {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) == 0 {
		return ""
	}

	i := 0
	if filepath.Base(parts[0]) == "env" {
		i = 1
		for i < len(parts) {
			p := parts[i]
			if strings.HasPrefix(p, "-") {
				if (p == "-u" || p == "--unset") && i+1 < len(parts) {
					i++
				}
				i++
				continue
			}
			if strings.Contains(p, "=") {
				i++
				continue
			}
			break
		}
	} else {
		for i < len(parts) && strings.Contains(parts[i], "=") && !strings.HasPrefix(parts[i], "-") {
			i++
		}
	}

	if i >= len(parts) {
		return ""
	}

	parts[i] = filepath.Base(parts[i])
	return strings.Join(parts[i:], " ")
}

// SplitCompoundCommand splits a command string on shell compound operators.
func SplitCompoundCommand(cmd string) []string {
	var segments []string
	var current strings.Builder
	runes := []rune(cmd)
	i := 0
	inSingle := false
	inDouble := false
	for i < len(runes) {
		ch := runes[i]

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
			segments = append(segments, current.String())
			current.Reset()
			if i+1 < len(runes) && runes[i+1] == '&' {
				i += 2
			} else {
				i++
			}
		case ';':
			segments = append(segments, current.String())
			current.Reset()
			i++
		case '\n', '\r':
			// Newline terminates a simple command exactly like `;`. Agents
			// routinely emit multi-line Bash; treating only `;`/`&`/`|` as
			// separators classified the whole block by its first line.
			segments = append(segments, current.String())
			current.Reset()
			if ch == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
				i += 2
			} else {
				i++
			}
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

// ExtractCommandSubstitutions returns the bodies of `$(...)`, `<(...)`,
// `>(...)`, and backtick command substitutions. The shell executes these
// before the enclosing command, so they must be classified as commands in
// their own right; otherwise `echo $(curl https://evil)` looks like `echo`.
// Single-quoted text is skipped (the shell does not expand it there).
func ExtractCommandSubstitutions(cmd string) []string {
	var out []string
	runes := []rune(cmd)
	inSingle := false
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if ch == '\'' {
			inSingle = !inSingle
			continue
		}
		if inSingle {
			continue
		}
		if ch == '`' {
			j := i + 1
			for j < len(runes) && runes[j] != '`' {
				j++
			}
			if j < len(runes) {
				out = append(out, string(runes[i+1:j]))
				i = j
			}
			continue
		}
		if ch == '$' && i+1 < len(runes) && runes[i+1] == '(' {
			out = append(out, extractBalancedSubstitution(runes, i+2, '(', ')'))
			i = skipBalanced(runes, i+2, '(', ')') - 1
			continue
		}
		if (ch == '<' || ch == '>') && i+1 < len(runes) && runes[i+1] == '(' {
			out = append(out, extractBalancedSubstitution(runes, i+2, '(', ')'))
			i = skipBalanced(runes, i+2, '(', ')') - 1
			continue
		}
	}
	return out
}

func extractBalancedSubstitution(runes []rune, start int, open, close rune) string {
	end := skipBalanced(runes, start, open, close)
	if end <= start || end > len(runes) {
		return ""
	}
	return string(runes[start : end-1])
}

func skipBalanced(runes []rune, start int, open, close rune) int {
	depth := 1
	for j := start; j < len(runes); j++ {
		switch runes[j] {
		case open:
			depth++
		case close:
			depth--
			if depth == 0 {
				return j + 1
			}
		}
	}
	return start
}

// StripSudoPrefix removes sudo and its flags to get the inner command.
func StripSudoPrefix(cmd string) string {
	trimmed := strings.TrimSpace(cmd)
	parts := strings.Fields(trimmed)
	if len(parts) < 2 {
		return ""
	}
	i := 1
	for i < len(parts) {
		if strings.HasPrefix(parts[i], "-") {
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

// ExtractShellWrapperInner returns the inner command from bash/sh -c wrappers.
func ExtractShellWrapperInner(cmd string) (string, bool) {
	parts := strings.Fields(strings.TrimSpace(cmd))
	if len(parts) < 3 {
		return "", false
	}

	switch strings.ToLower(filepath.Base(parts[0])) {
	case "bash", "sh", "zsh", "dash", "ksh":
	default:
		return "", false
	}

	cIndex := -1
	for i := 1; i < len(parts); i++ {
		p := parts[i]
		if p == "-c" {
			cIndex = i
			break
		}
		if strings.HasPrefix(p, "-") && !strings.HasPrefix(p, "--") && strings.HasSuffix(p, "c") {
			cIndex = i
			break
		}
		if strings.HasPrefix(p, "-") {
			continue
		}
		return "", false
	}

	if cIndex < 0 || cIndex+1 >= len(parts) {
		return "", false
	}

	inner := strings.TrimSpace(strings.Join(parts[cIndex+1:], " "))
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

// FlagTakesValue reports whether a curl/wget flag consumes the next argument.
func FlagTakesValue(flag string) bool {
	valuedFlags := []string{
		"-d", "--data", "--data-binary", "--data-urlencode", "--data-raw",
		"-F", "--form", "--form-string",
		"-X", "--request",
		"-H", "--header", "-A", "--user-agent", "-e", "--referer",
		"-b", "--cookie", "-c", "--cookie-jar",
		"-u", "--user", "--oauth2-bearer",
		"-o", "--output", "-T", "--upload-file",
		"-w", "--write-out",
		"--cacert", "--cert", "--key", "--ciphers",
		"--resolve", "--interface", "--local-port",
		"--connect-timeout", "-m", "--max-time",
		"--max-redirs", "--retry", "--retry-delay", "--retry-max-time",
		"-x", "--proxy", "-U", "--proxy-user",
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
