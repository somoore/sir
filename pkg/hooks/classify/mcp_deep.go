package classify

import "strings"

// shellLikeKeys identifies MCP tool argument keys that conventionally
// carry shell command strings. Matched against a normalized form of the
// field name (lowercase, no non-alphanumeric). New additions should be
// obvious shell-adjacent names; anything clever here increases false
// positives more than it catches real misuse.
var shellLikeKeys = map[string]struct{}{
	"command":    {},
	"commands":   {},
	"cmd":        {},
	"cmds":       {},
	"shell":      {},
	"script":     {},
	"scripts":    {},
	"exec":       {},
	"run":        {},
	"bash":       {},
	"sh":         {},
	"shellcmd":   {},
	"execcmd":    {},
	"shellexec":  {},
	"runcommand": {},
}

// writeLikeKeys identifies MCP tool argument keys that conventionally
// carry filesystem paths intended for writing. These are the keys most
// likely to hit CLAUDE.md, .env, posture files, etc. when exposed by a
// naive MCP server that wraps filesystem primitives.
var writeLikeKeys = map[string]struct{}{
	"path":        {},
	"paths":       {},
	"filepath":    {},
	"file":        {},
	"files":       {},
	"dest":        {},
	"destination": {},
	"target":      {},
	"targetpath":  {},
	"output":      {},
	"outputs":     {},
	"outputpath":  {},
	"writepath":   {},
}

// FirstShellLikeValue walks toolInput and returns the first non-empty
// string value whose key matches a shellLikeKeys entry. Depth-limited to
// match ExtractMCPURLs; shell-like payloads buried more than 8 levels
// deep are ignored (deliberately).
//
// Known limitation: field-rename evasion (`task_spec`, `instruction`,
// `payload_b64`) is out of scope by design. This helper catches honest
// MCPs that expose shell wrappers under conventional field names. It
// does not catch malicious MCPs that deliberately obfuscate.
func FirstShellLikeValue(toolInput map[string]interface{}) string {
	return firstValueMatchingKey(toolInput, shellLikeKeys)
}

// FirstWriteLikePath walks toolInput and returns the first non-empty
// string value whose key matches writeLikeKeys. Caller should further
// classify the path (posture/sensitive) before acting on it, since many
// legitimate paths also appear under these keys.
func FirstWriteLikePath(toolInput map[string]interface{}) string {
	return firstValueMatchingKey(toolInput, writeLikeKeys)
}

func firstValueMatchingKey(toolInput map[string]interface{}, keys map[string]struct{}) string {
	if toolInput == nil {
		return ""
	}
	var found string
	var walk func(interface{}, string, int)
	walk = func(v interface{}, key string, depth int) {
		if found != "" || depth > maxMCPURLDepth {
			return
		}
		switch val := v.(type) {
		case string:
			if key == "" {
				return
			}
			if _, ok := keys[normalizeMCPKey(key)]; !ok {
				return
			}
			trimmed := strings.TrimSpace(val)
			if trimmed == "" {
				return
			}
			found = trimmed
		case map[string]interface{}:
			for k, child := range val {
				walk(child, k, depth+1)
				if found != "" {
					return
				}
			}
		case []interface{}:
			for _, child := range val {
				// Arrays inherit the parent key for classification so
				// `{"commands": ["curl evil.com"]}` still triggers.
				walk(child, key, depth+1)
				if found != "" {
					return
				}
			}
		}
	}
	walk(toolInput, "", 0)
	return found
}

// normalizeMCPKey lowercases and strips non-alphanumeric characters so
// `file_path`, `FilePath`, and `file-path` all collapse to "filepath".
// Matches the behavior in pkg/hooks/evaluate_preflight.go for
// path-bearing key detection, deliberately not deduplicated because the
// existing helper lives in an unexported name in another package.
func normalizeMCPKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for _, r := range key {
		switch {
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r + ('a' - 'A'))
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}
