package secretscan

import "strings"

// credentialPatterns are substrings in MCP tool argument values that suggest
// credentials are being passed. These are checked when the session carries
// secrets and the MCP server is not trusted.
var credentialPatterns = []string{
	"sk-", "pk-", "Bearer ", "token:", "api_key",
	"apikey", "api-key", "access_token", "refresh_token",
	"auth_token", "secret_key", "private_key",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_",
	"AKIA", "aws_secret", "aws_access",
	"password:", "password\":", "passwd:", "credential",
	"-----BEGIN", "-----END",
}

// sensitiveKeyNames are key names that indicate the value is a credential,
// regardless of what the value looks like.
var sensitiveKeyNames = []string{
	"password", "passwd", "secret", "api_key", "apikey", "api-key",
	"access_token", "auth_token", "token", "private_key", "credential",
	"aws_secret_access_key", "aws_access_key_id",
}

// RedactMCPValue redacts a string value from an MCP argument payload.
// The key name is considered because MCP credential scanning also treats
// sensitive field names as credential-bearing even when the raw value lacks
// a distinctive structural prefix.
func RedactMCPValue(key, value string) string {
	redacted := RedactStructuredText(value)
	if redacted != value {
		return redacted
	}
	if found, label := sensitiveMCPIndicator(key, value); found {
		return "[REDACTED:" + label + "]"
	}
	return value
}

// ScanMCPArgsForCredentials checks MCP tool arguments for credential patterns.
// Called for all untrusted MCP server calls.
func ScanMCPArgsForCredentials(toolInput map[string]interface{}) (bool, string) {
	return scanArgsRecursive(toolInput, "")
}

// ScanStringForCredentials checks a raw string for credential patterns.
// Used by mcp-proxy to scan stderr output from MCP server processes.
func ScanStringForCredentials(s string) (bool, string) {
	return checkCredentialString("", s)
}

func scanArgsRecursive(obj map[string]interface{}, path string) (bool, string) {
	for key, val := range obj {
		fullKey := key
		if path != "" {
			fullKey = path + "." + key
		}
		switch v := val.(type) {
		case string:
			if found, hint := checkCredentialString(fullKey, v); found {
				return true, hint
			}
		case map[string]interface{}:
			if found, hint := scanArgsRecursive(v, fullKey); found {
				return true, hint
			}
		case []interface{}:
			for i, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					if found, hint := scanArgsRecursive(m, fullKey+"["+itoa(i)+"]"); found {
						return true, hint
					}
				}
				if s, ok := item.(string); ok {
					if found, hint := checkCredentialString(fullKey, s); found {
						return true, hint
					}
				}
			}
		}
	}
	return false, ""
}

func checkCredentialString(key, val string) (bool, string) {
	lower := strings.ToLower(val)
	for _, pat := range credentialPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true, key + " contains " + pat
		}
	}
	lowerKey := strings.ToLower(key)
	for _, sk := range sensitiveKeyNames {
		if lowerKey == sk || strings.HasSuffix(lowerKey, "."+sk) {
			if strings.TrimSpace(val) != "" {
				return true, key + " is a sensitive key name"
			}
		}
	}
	if len(val) > 100 && looksBase64(val) {
		return true, key + " contains long base64-like value"
	}
	return false, ""
}

func sensitiveMCPIndicator(key, value string) (bool, string) {
	lowerKey := strings.ToLower(key)
	for _, sk := range sensitiveKeyNames {
		if lowerKey == sk || strings.HasSuffix(lowerKey, "."+sk) {
			if strings.TrimSpace(value) != "" {
				return true, "sensitive_key"
			}
		}
	}
	lower := strings.ToLower(value)
	for _, pat := range credentialPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true, "sensitive_value"
		}
	}
	if len(value) > 100 && looksBase64(value) {
		return true, "long_token"
	}
	return false, ""
}

func looksBase64(s string) bool {
	if strings.Contains(s, " ") {
		return false
	}
	alphaNum := 0
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			alphaNum++
		}
	}
	return len(s) > 0 && float64(alphaNum)/float64(len(s)) > 0.9
}

func itoa(v int) string {
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
