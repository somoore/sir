package ledger

import (
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/somoore/sir/pkg/secretscan"
)

const longTokenRedaction = "[REDACTED:long_token]" // #nosec G101 -- literal redaction marker, not a credential

// SliceHeadTail captures the first and last sliceBytes of content, trimming
// each side to a safe word boundary. Short content is returned unchanged.
func SliceHeadTail(content string, sliceBytes int) string {
	if content == "" || sliceBytes <= 0 {
		return content
	}
	if len(content) <= sliceBytes*2 {
		return content
	}

	head := trimSegmentToBoundary(content[:safePrefixBoundary(content, sliceBytes)], sliceBytes)
	tail := trimLeadingPartialToken(content[len(content)-sliceBytes:])

	if head == "" && tail == "" {
		return ""
	}
	if head == "" {
		return tail
	}
	if tail == "" {
		return head
	}
	return head + "\n...[truncated]...\n" + tail
}

// TruncateToWordBoundary truncates the string at a word boundary within the
// final 64 bytes. If the boundary cannot be found, the segment is treated as a
// long token and redacted wholesale.
func TruncateToWordBoundary(s string, maxBytes int) string {
	if s == "" || maxBytes <= 0 {
		return ""
	}
	if len(s) <= maxBytes {
		return s
	}
	return trimSegmentToBoundary(s, maxBytes)
}

// RedactString applies the shared credential pattern table to a string value.
func RedactString(s string) string {
	if s == "" {
		return ""
	}
	redacted := secretscan.RedactStructuredText(s)
	if redacted != s {
		return redacted
	}
	if strings.Contains(s, "Bearer ") {
		return "[REDACTED:credential]"
	}
	return redacted
}

// RedactMapValues returns a deep-copied map with every string value redacted
// before serialization.
func RedactMapValues(m map[string]interface{}) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for key, value := range m {
		out[key] = redactAnyValue(key, value)
	}
	return out
}

// RedactContent slices the content to the same head/tail windows used by the
// MCP injection scanner and then applies credential redaction.
func RedactContent(content string, sliceBytes int) string {
	if content == "" {
		return ""
	}
	return RedactString(SliceHeadTail(content, sliceBytes))
}

// RedactEvidence preserves structured JSON evidence when possible while still
// redacting sensitive values. Non-JSON evidence falls back to bounded text
// redaction.
func RedactEvidence(content string) string {
	if content == "" {
		return ""
	}
	var value interface{}
	if err := json.Unmarshal([]byte(content), &value); err == nil {
		data, marshalErr := json.Marshal(redactAnyValue("", value))
		if marshalErr == nil {
			return TruncateToWordBoundary(string(data), 2048)
		}
	}
	return RedactContent(content, 1024)
}

func redactAnyValue(path string, value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		if strings.HasPrefix(v, "[REDACTED:") && strings.HasSuffix(v, "]") {
			return v
		}
		return secretscan.RedactMCPValue(path, v)
	case map[string]interface{}:
		return RedactMapValuesWithPath(path, v)
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for i, item := range v {
			childPath := path + "[" + strconvItoa(i) + "]"
			out = append(out, redactAnyValue(childPath, item))
		}
		return out
	default:
		return value
	}
}

func RedactMapValuesWithPath(path string, m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for key, value := range m {
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		out[key] = redactAnyValue(childPath, value)
	}
	return out
}

func trimSegmentToBoundary(s string, maxBytes int) string {
	if s == "" {
		return ""
	}
	if len(s) > maxBytes {
		s = s[:safePrefixBoundary(s, maxBytes)]
	}
	searchFloor := len(s) - 64
	if searchFloor < 0 {
		searchFloor = 0
	}
	for i := len(s); i > searchFloor; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		if r == utf8.RuneError && size == 1 {
			i--
			continue
		}
		if isBoundaryRune(r) {
			return s[:i]
		}
		i -= size
	}
	for i := searchFloor; i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		if r == utf8.RuneError && size == 1 {
			i--
			continue
		}
		if isBoundaryRune(r) {
			return s[:i]
		}
		i -= size
	}
	return longTokenRedaction
}

func trimLeadingPartialToken(s string) string {
	if s == "" {
		return ""
	}
	r, size := utf8.DecodeRuneInString(s)
	if r == utf8.RuneError && size == 1 {
		return s
	}
	if isBoundaryRune(r) {
		return s
	}
	consumed := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			i++
			consumed++
			continue
		}
		if isBoundaryRune(r) {
			return strings.TrimLeftFunc(s[i:], isBoundaryRune)
		}
		i += size
		consumed += size
		if consumed > 64 && i >= len(s) {
			break
		}
	}
	return longTokenRedaction
}

func isBoundaryRune(r rune) bool {
	if unicode.IsSpace(r) {
		return true
	}
	if unicode.IsLetter(r) || unicode.IsDigit(r) {
		return false
	}
	switch r {
	case '_', '-', '=', '+', '/':
		return false
	default:
		return true
	}
}

func safePrefixBoundary(s string, maxBytes int) int {
	if len(s) <= maxBytes {
		return len(s)
	}
	cut := maxBytes
	for cut > 0 && !utf8.ValidString(s[:cut]) {
		cut--
	}
	if cut == 0 {
		return maxBytes
	}
	return cut
}

func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
