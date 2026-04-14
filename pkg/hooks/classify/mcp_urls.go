package classify

import "strings"

// ExtractMCPURLs walks an MCP tool input and returns URL-shaped string values.
//
// Scope: this is an intentionally narrow heuristic. It catches Claude passing
// a literal URL to an MCP server. It does NOT catch field-split URLs
// (host+path in separate keys), base64/encoded URLs, or URLs the server
// constructs server-side from non-URL inputs. Those escapes are a known
// limitation — containment for malicious MCPs is the OS sandbox in
// `sir mcp-proxy`, not this classifier.
func ExtractMCPURLs(toolInput map[string]interface{}) []string {
	if toolInput == nil {
		return nil
	}
	var urls []string
	collectURLs(toolInput, &urls, 0)
	return urls
}

const (
	maxMCPURLDepth = 8
	maxMCPURLs     = 64
)

func collectURLs(v interface{}, out *[]string, depth int) {
	if depth > maxMCPURLDepth || len(*out) >= maxMCPURLs {
		return
	}
	switch val := v.(type) {
	case string:
		if u := urlFromString(val); u != "" {
			*out = append(*out, u)
		}
	case map[string]interface{}:
		for _, child := range val {
			collectURLs(child, out, depth+1)
			if len(*out) >= maxMCPURLs {
				return
			}
		}
	case []interface{}:
		for _, child := range val {
			collectURLs(child, out, depth+1)
			if len(*out) >= maxMCPURLs {
				return
			}
		}
	}
}

// urlFromString returns the string if it parses as an http(s) URL with a
// non-empty host, else "". Other schemes (file://, git://, ssh://, data:)
// are ignored here; they are not the allow-host gate's concern.
func urlFromString(s string) string {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || len(trimmed) > 2048 {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return ""
	}
	if ExtractHost(trimmed) == "" {
		return ""
	}
	return trimmed
}
