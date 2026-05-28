// Package secretview produces a redacted, presence-only view of a sensitive
// file. It answers "what keys/credentials are in here" without ever returning
// a value, so a developer or agent can stay productive after a sensitive-read
// block without raw secret exposure. Raw values are a separate, explicit
// approval — this package never emits them.
package secretview

import (
	"strings"

	"github.com/somoore/sir/pkg/secretscan"
)

// Entry is a single redacted key from an env-style file.
type Entry struct {
	Key      string `json:"key"`
	Present  bool   `json:"present"`
	ValueLen int    `json:"value_len"`
	Class    string `json:"class,omitempty"` // credential pattern name, when recognized
}

// View is the redacted summary of a sensitive file. For env-style files it
// lists keys with masked values; for opaque files it reports a structural
// summary and how many credential-like patterns were detected.
type View struct {
	Kind           string  `json:"kind"` // "env" or "opaque"
	Entries        []Entry `json:"entries,omitempty"`
	Lines          int     `json:"lines"`
	Bytes          int     `json:"bytes"`
	CommentLines   int     `json:"comment_lines,omitempty"`
	CredentialHits int     `json:"credential_hits,omitempty"`
}

// Redact builds a redacted View of content. The name (basename or path) is
// used as a hint to prefer env parsing for .env-style files; content shape is
// the fallback signal. Values are never copied into the View.
func Redact(name string, content []byte) View {
	text := string(content)
	v := View{Bytes: len(content)}
	lines := strings.Split(text, "\n")
	v.Lines = len(lines)

	if looksLikeEnv(name, lines) {
		v.Kind = "env"
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "#") {
				v.CommentLines++
				continue
			}
			key, value, ok := splitEnvLine(trimmed)
			if !ok {
				continue
			}
			entry := Entry{Key: key, Present: value != "", ValueLen: len(value)}
			if value != "" {
				entry.Class = classify(value)
				if entry.Class != "" {
					v.CredentialHits++
				}
			}
			v.Entries = append(v.Entries, entry)
		}
		return v
	}

	v.Kind = "opaque"
	v.CredentialHits = len(secretscan.ScanOutputForCredentials(text))
	return v
}

// looksLikeEnv reports whether the file should be parsed as KEY=VALUE. A .env
// name is decisive; otherwise we require that most non-blank, non-comment lines
// parse as assignments.
func looksLikeEnv(name string, lines []string) bool {
	base := name
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	if base == ".env" || strings.HasPrefix(base, ".env") || strings.HasSuffix(base, ".env") {
		return true
	}
	var considered, assignments int
	for _, line := range lines {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		considered++
		if _, _, ok := splitEnvLine(t); ok {
			assignments++
		}
	}
	return considered > 0 && assignments*2 >= considered // majority are assignments
}

// splitEnvLine parses "KEY=VALUE", "export KEY=VALUE", and quoted values. It
// returns the key and the unquoted value; ok is false when the line is not an
// assignment or the key is not a plausible identifier.
func splitEnvLine(line string) (key, value string, ok bool) {
	line = strings.TrimPrefix(line, "export ")
	i := strings.Index(line, "=")
	if i <= 0 {
		return "", "", false
	}
	key = strings.TrimSpace(line[:i])
	value = strings.TrimSpace(line[i+1:])
	value = strings.TrimSuffix(strings.TrimPrefix(value, `"`), `"`)
	value = strings.TrimSuffix(strings.TrimPrefix(value, `'`), `'`)
	if !validKey(key) {
		return "", "", false
	}
	return key, value, true
}

func validKey(key string) bool {
	if key == "" {
		return false
	}
	for _, r := range key {
		if !(r == '_' || r == '.' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

// classify returns the credential pattern name for a value, or "" if it does
// not match a known credential shape. The value itself is never returned.
func classify(value string) string {
	matches := secretscan.ScanOutputForCredentials(value)
	if len(matches) > 0 {
		return matches[0].PatternName
	}
	return ""
}
