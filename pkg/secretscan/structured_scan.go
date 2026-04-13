package secretscan

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

var outputPatterns = []Pattern{
	// High confidence — distinctive structural prefixes.
	{Name: "aws_access_key", RedactionLabel: "aws_access_key", RE: regexp.MustCompile(`AKIA[0-9A-Z]{16}`), Confidence: "high"},
	{Name: "github_pat", RedactionLabel: "github_pat", RE: regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`), Confidence: "high"},
	{Name: "github_fine_grained_pat", RedactionLabel: "github_pat", RE: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82}`), Confidence: "high"},
	{Name: "github_oauth", RedactionLabel: "github_oauth", RE: regexp.MustCompile(`gho_[A-Za-z0-9]{36}`), Confidence: "high"},
	{Name: "github_user_to_server", RedactionLabel: "github_user_to_server", RE: regexp.MustCompile(`ghu_[A-Za-z0-9]{36}`), Confidence: "high"},
	{Name: "github_server_to_server", RedactionLabel: "github_server_to_server", RE: regexp.MustCompile(`ghs_[A-Za-z0-9]{36}`), Confidence: "high"},
	{Name: "github_refresh", RedactionLabel: "github_refresh", RE: regexp.MustCompile(`ghr_[A-Za-z0-9]{36}`), Confidence: "high"},
	{Name: "slack_bot_token", RedactionLabel: "slack_bot_token", RE: regexp.MustCompile(`xoxb-[A-Za-z0-9\-]{10,}`), Confidence: "high"},
	{Name: "slack_user_token", RedactionLabel: "slack_user_token", RE: regexp.MustCompile(`xoxp-[A-Za-z0-9\-]{10,}`), Confidence: "high"},
	{Name: "stripe_secret_key", RedactionLabel: "stripe_live", RE: regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`), Confidence: "high"},
	{Name: "stripe_publishable_key", RedactionLabel: "stripe_publishable", RE: regexp.MustCompile(`pk_live_[A-Za-z0-9]{24,}`), Confidence: "high"},
	{Name: "stripe_restricted_key", RedactionLabel: "stripe_restricted", RE: regexp.MustCompile(`rk_live_[A-Za-z0-9]{24,}`), Confidence: "high"},
	{Name: "google_api_key", RedactionLabel: "google_api_key", RE: regexp.MustCompile(`AIza[0-9A-Za-z_\-]{35}`), Confidence: "high"},
	{Name: "private_key_header", RedactionLabel: "pem_header", RE: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), Confidence: "high"},
	{Name: "openai_api_key", RedactionLabel: "openai_api_key", RE: regexp.MustCompile(`sk-[A-Za-z0-9_\-]{20,}`), Confidence: "high"},

	// Medium confidence — broader formats with validators.
	{Name: "jwt", RedactionLabel: "jwt", RE: regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+`), Confidence: "medium"},
	{Name: "ssn", RedactionLabel: "ssn", RE: regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), Confidence: "medium", Validator: validateSSN},
	{Name: "credit_card", RedactionLabel: "credit_card", RE: regexp.MustCompile(`\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{1,7}\b`), Confidence: "medium", Validator: validateLuhn},
}

const scanWindowBytes = 100 * 1024
const largeOutputThreshold = 200 * 1024

// ScanOutputForCredentials scans tool output text for structured secret patterns.
// Returns a deduplicated list of matches (one per pattern name). Never stores or
// logs actual credential values.
func ScanOutputForCredentials(output string) []CredentialMatch {
	if output == "" {
		return nil
	}

	var scanText string
	if len(output) > largeOutputThreshold {
		scanText = output[:scanWindowBytes] + "\n" + output[len(output)-scanWindowBytes:]
	} else {
		scanText = output
	}

	seen := make(map[string]struct{})
	var matches []CredentialMatch

	for _, p := range outputPatterns {
		if _, dup := seen[p.Name]; dup {
			continue
		}
		found := p.RE.FindAllString(scanText, -1)
		if len(found) == 0 {
			continue
		}
		if p.Validator != nil {
			validated := false
			for _, m := range found {
				if p.Validator(m) {
					validated = true
					break
				}
			}
			if !validated {
				continue
			}
		}
		seen[p.Name] = struct{}{}
		matches = append(matches, CredentialMatch{
			PatternName: p.Name,
			Confidence:  p.Confidence,
		})
	}

	if _, dup := seen["high_entropy_token"]; !dup {
		for _, tok := range strings.Fields(scanText) {
			if IsHighEntropyString(tok) {
				matches = append(matches, CredentialMatch{
					PatternName: "high_entropy_token",
					Confidence:  "medium",
				})
				break
			}
		}
	}

	return matches
}

// RedactStructuredText replaces structured credential matches with
// [REDACTED:<label>] placeholders.
func RedactStructuredText(s string) string {
	if s == "" {
		return ""
	}
	redacted := s
	for _, pattern := range outputPatterns {
		replacement := "[REDACTED:" + pattern.RedactionLabel + "]"
		redacted = pattern.RE.ReplaceAllStringFunc(redacted, func(match string) string {
			if pattern.Validator != nil && !pattern.Validator(match) {
				return match
			}
			return replacement
		})
	}
	return redactHighEntropyTokens(redacted)
}

// IsHighEntropyString returns true if s looks like a random secret token:
// at least 32 chars, no whitespace, no URL/markup syntax, and Shannon
// entropy >4.5 bits/char.
//
// Real credential tokens are alphanumeric with limited special characters
// (dashes, underscores, dots, slashes for JWT segments). Tokens containing
// URL indicators (://), markdown/HTML brackets ([]()<>), query strings (?&=),
// or pipe characters are not credentials — they are URLs, badge markup,
// env var examples, or similar structured text that happens to be long and
// varied. Filtering these out prevents false positives on README badge URLs,
// config examples, and markdown link syntax.
func IsHighEntropyString(s string) bool {
	if len(s) < 32 {
		return false
	}
	if strings.ContainsAny(s, " \t\n\r") {
		return false
	}
	// Exclude URL, markup, and structured-data syntax — real API keys/tokens
	// are alphanumeric with limited special characters (dashes, underscores,
	// dots, slashes for JWT segments). They never contain JSON braces, HTML
	// brackets, URL query parameters, or similar structural characters.
	if strings.Contains(s, "://") ||
		strings.ContainsAny(s, "[]()<>{}|?&=:,\"") {
		return false
	}
	if looksLikePathishToken(s) {
		return false
	}
	return shannonEntropy(s) > 4.5
}

func OutputPatterns() []Pattern {
	out := make([]Pattern, len(outputPatterns))
	copy(out, outputPatterns)
	return out
}

func looksLikePathishToken(s string) bool {
	switch {
	case strings.HasPrefix(s, "/"),
		strings.HasPrefix(s, "./"),
		strings.HasPrefix(s, "../"),
		strings.HasPrefix(s, "~/"),
		strings.HasPrefix(s, ".\\"),
		strings.HasPrefix(s, "..\\"),
		strings.HasPrefix(s, "~\\"):
		return true
	}

	// Windows drive-letter absolute paths (C:\foo or C:/foo).
	if len(s) >= 3 &&
		((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) &&
		s[1] == ':' &&
		(s[2] == '\\' || s[2] == '/') {
		return true
	}

	// Relative path-like tokens with multiple segments and a filename suffix,
	// e.g. detection/splunk/apfelbauer-rules.spl
	if strings.Count(s, "/") >= 2 {
		lastSlash := strings.LastIndex(s, "/")
		if lastSlash >= 0 {
			base := s[lastSlash+1:]
			if strings.Contains(base, ".") {
				return true
			}
		}
	}

	return false
}

func ValidateLuhn(s string) bool {
	return validateLuhn(s)
}

func ValidateSSN(s string) bool {
	return validateSSN(s)
}

func ShannonEntropy(s string) float64 {
	return shannonEntropy(s)
}

func redactHighEntropyTokens(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	tokenStart := -1
	for i, r := range s {
		if unicode.IsSpace(r) {
			if tokenStart >= 0 {
				b.WriteString(redactTokenIfNeeded(s[tokenStart:i]))
				tokenStart = -1
			}
			b.WriteRune(r)
			continue
		}
		if tokenStart < 0 {
			tokenStart = i
		}
	}
	if tokenStart >= 0 {
		b.WriteString(redactTokenIfNeeded(s[tokenStart:]))
	}
	return b.String()
}

func redactTokenIfNeeded(token string) string {
	if IsHighEntropyString(token) {
		return "[REDACTED:high_entropy_token]"
	}
	return token
}

func validateLuhn(s string) bool {
	digits := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			digits = append(digits, c-'0')
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := len(digits) - 1; i >= 0; i-- {
		n := int(digits[i])
		if alt {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		alt = !alt
	}
	return sum%10 == 0
}

func validateSSN(match string) bool {
	if len(match) != 11 {
		return false
	}
	if match[3] != '-' || match[6] != '-' {
		return false
	}
	area := match[0:3]
	group := match[4:6]
	serial := match[7:11]

	if area == "000" || area == "666" {
		return false
	}
	if area[0] == '9' {
		return false
	}
	if group == "00" {
		return false
	}
	if serial == "0000" {
		return false
	}
	return true
}

func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]int)
	total := 0
	for _, r := range s {
		freq[r]++
		total++
	}
	if total == 0 {
		return 0
	}
	length := float64(total)
	entropy := 0.0
	for _, count := range freq {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
