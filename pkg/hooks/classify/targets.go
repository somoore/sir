package classify

import (
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

func normalizePath(path string) string {
	clean := filepath.Clean(path)
	if runtime.GOOS == "darwin" {
		return strings.ToLower(clean)
	}
	return clean
}

// ResolveTarget canonicalizes a target path against projectRoot.
func ResolveTarget(projectRoot, target string) string {
	if target == "" {
		return ""
	}
	if target == "~" || strings.HasPrefix(target, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			target = filepath.Join(home, strings.TrimPrefix(target, "~"))
		}
	}
	var abs string
	if filepath.IsAbs(target) {
		abs = filepath.Clean(target)
	} else {
		abs = filepath.Clean(filepath.Join(projectRoot, target))
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	if runtime.GOOS == "darwin" {
		return strings.ToLower(abs)
	}
	return abs
}

func IsPostureFile(target string, l *lease.Lease) bool {
	norm := normalizePath(target)
	for _, path := range l.PostureFiles {
		if matchPath(norm, normalizePath(path)) {
			return true
		}
	}
	return false
}

func IsSensitivePath(target string, l *lease.Lease) bool {
	norm := normalizePath(target)
	base := filepath.Base(norm)
	for _, suffix := range []string{".example", ".sample", ".template"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	for _, excluded := range l.SensitivePathExclusions {
		if matchPath(norm, normalizePath(excluded)) {
			return false
		}
	}
	for _, path := range l.SensitivePaths {
		if matchPath(norm, normalizePath(path)) {
			return true
		}
	}
	return false
}

func IsSensitivePathResolved(target string, l *lease.Lease) bool {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return IsSensitivePath(target, l)
	}
	return IsSensitivePath(resolved, l)
}

func IsSensitivePathResolvedIn(projectRoot, target string, l *lease.Lease) bool {
	canonical := ResolveTarget(projectRoot, target)
	if canonical == "" {
		return IsSensitivePathResolved(target, l)
	}
	return IsSensitivePath(canonical, l)
}

func IsPostureFileResolved(target string, l *lease.Lease) bool {
	resolved, err := filepath.EvalSymlinks(target)
	if err != nil {
		return IsPostureFile(target, l)
	}
	return IsPostureFile(resolved, l)
}

func IsPostureFileResolvedIn(projectRoot, target string, l *lease.Lease) bool {
	canonical := ResolveTarget(projectRoot, target)
	if canonical == "" {
		return IsPostureFileResolved(target, l)
	}
	return IsPostureFile(canonical, l)
}

func ClassifyNetworkDest(target string, l *lease.Lease) string {
	host := ExtractHost(target)
	if host == "" {
		return "external"
	}
	if isLoopback(host) {
		return "loopback"
	}
	if l != nil && l.IsApprovedHost(host) {
		return "approved"
	}
	return "external"
}

func ClassifyGitRemote(cmd string, l *lease.Lease) string {
	remote := ExtractGitRemote(cmd)
	if remote == "" {
		remote = "origin"
	}
	for _, approved := range l.ApprovedRemotes {
		if remote == approved {
			return "approved"
		}
	}
	return "unapproved"
}

func IsEphemeralExec(cmd string) bool {
	trimmed := strings.TrimSpace(cmd)
	return strings.HasPrefix(trimmed, "npx ") || trimmed == "npx"
}

func ExtractHost(target string) string {
	if strings.Contains(target, "://") {
		u, err := url.Parse(target)
		if err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		return host
	}
	return strings.TrimSpace(target)
}

func ExtractGitRemote(cmd string) string {
	parts := strings.Fields(cmd)
	pushIdx := -1
	for i, part := range parts {
		if part == "push" {
			pushIdx = i
			break
		}
	}
	if pushIdx < 0 || pushIdx+1 >= len(parts) {
		return ""
	}
	for i := pushIdx + 1; i < len(parts); i++ {
		token := parts[i]
		if isShellMetaToken(token) {
			return ""
		}
		if strings.HasPrefix(token, "-") {
			continue
		}
		return token
	}
	return ""
}

func isLoopback(host string) bool {
	for _, loopback := range []string{
		"localhost", "127.0.0.1", "::1", "[::1]",
		"host.docker.internal",
	} {
		if strings.EqualFold(host, loopback) {
			return true
		}
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func isShellMetaToken(token string) bool {
	if token == "" {
		return false
	}
	for _, prefix := range []string{
		"2>&1", "&>", "2>", "1>",
		">>", "<<",
		">", "<",
		"||", "&&",
		"|", "&", ";",
	} {
		if strings.HasPrefix(token, prefix) {
			return true
		}
	}
	return false
}

func matchPath(path, pattern string) bool {
	if strings.Contains(pattern, "**") {
		parts := strings.SplitN(pattern, "**", 2)
		prefix := parts[0]
		suffix := ""
		if len(parts) > 1 {
			suffix = parts[1]
		}
		if prefix != "" && !strings.HasPrefix(path, strings.TrimRight(prefix, "/")) {
			return false
		}
		if suffix != "" {
			suffix = strings.TrimLeft(suffix, "/")
			remaining := path
			if prefix != "" {
				remaining = strings.TrimPrefix(path, strings.TrimRight(prefix, "/"))
				remaining = strings.TrimLeft(remaining, "/")
			}
			segments := strings.Split(remaining, "/")
			for i := range segments {
				subpath := strings.Join(segments[i:], "/")
				matched, _ := filepath.Match(suffix, subpath)
				if matched {
					return true
				}
			}
			matched, _ := filepath.Match(suffix, filepath.Base(path))
			return matched
		}
		return true
	}

	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}
	return matchPathTail(path, pattern)
}

func matchPathTail(path, pattern string) bool {
	pathSlash := filepath.ToSlash(filepath.Clean(path))
	patternSlash := filepath.ToSlash(pattern)

	pathParts := strings.Split(pathSlash, "/")
	patternParts := strings.Split(patternSlash, "/")

	filteredPath := make([]string, 0, len(pathParts))
	for _, part := range pathParts {
		if part != "" {
			filteredPath = append(filteredPath, part)
		}
	}
	filteredPattern := make([]string, 0, len(patternParts))
	for _, part := range patternParts {
		if part != "" {
			filteredPattern = append(filteredPattern, part)
		}
	}
	if len(filteredPattern) == 0 || len(filteredPath) < len(filteredPattern) {
		return false
	}
	tail := strings.Join(filteredPath[len(filteredPath)-len(filteredPattern):], "/")
	matched, _ := filepath.Match(strings.Join(filteredPattern, "/"), tail)
	return matched
}
