package evidence

import (
	"strings"

	"github.com/somoore/sir/pkg/secretscan"
)

// InjectionSignal describes a prompt injection pattern found in MCP response output.
type InjectionSignal struct {
	Pattern  string
	Severity string
	Context  string
}

type injectionPattern struct {
	needle       string
	severity     string
	contextAware bool
}

var injectionPatterns = []injectionPattern{
	{needle: "<|im_start|>", severity: "HIGH"},
	{needle: "<|im_end|>", severity: "HIGH"},
	{needle: "<|endoftext|>", severity: "HIGH"},
	{needle: "[INST]", severity: "HIGH"},
	{needle: "[/INST]", severity: "HIGH"},
	{needle: "<<SYS>>", severity: "HIGH"},
	{needle: "<</SYS>>", severity: "HIGH"},
	{needle: "SYSTEM:", severity: "HIGH"},
	{needle: "system:", severity: "HIGH", contextAware: true},
	{needle: "Human:", severity: "HIGH", contextAware: true},
	{needle: "Assistant:", severity: "HIGH", contextAware: true},
	{needle: "ignore previous instructions", severity: "HIGH"},
	{needle: "ignore all previous", severity: "HIGH"},
	{needle: "disregard previous", severity: "HIGH"},
	{needle: "forget your instructions", severity: "HIGH"},
	{needle: "new instructions:", severity: "HIGH"},
	{needle: "override instructions", severity: "HIGH"},
	{needle: "you are now", severity: "MEDIUM", contextAware: true},
	{needle: "you do not have limitations", severity: "HIGH"},
	{needle: "you do not have restrictions", severity: "HIGH"},
	{needle: "you lack restrictions", severity: "HIGH"},
	{needle: "you lack limitations", severity: "HIGH"},
	{needle: "you ignore safety", severity: "HIGH"},
	{needle: "you ignore ethical", severity: "HIGH"},
	{needle: "hypothetically", severity: "MEDIUM", contextAware: true},
	{needle: "imagine you", severity: "MEDIUM", contextAware: true},
	{needle: "suppose you", severity: "MEDIUM", contextAware: true},
	{needle: "pretend you are", severity: "MEDIUM", contextAware: true},
	{needle: "no safety guidelines", severity: "HIGH"},
	{needle: "no restrictions", severity: "HIGH"},
	{needle: "without safety", severity: "HIGH"},
	{needle: "without restrictions", severity: "HIGH"},
	{needle: "<!--", severity: "MEDIUM", contextAware: true},
	{needle: "base64:", severity: "MEDIUM", contextAware: true},
	{needle: "eval(", severity: "MEDIUM"},
	{needle: "call the", severity: "MEDIUM", contextAware: true},
	{needle: "use the tool", severity: "MEDIUM"},
	{needle: "execute the following", severity: "MEDIUM"},
	{needle: "run this command", severity: "MEDIUM"},
	{needle: "curl ", severity: "MEDIUM", contextAware: true},
	{needle: "wget ", severity: "MEDIUM", contextAware: true},
	{needle: "send this to", severity: "MEDIUM"},
	{needle: "post this to", severity: "MEDIUM"},
	{needle: "upload to", severity: "MEDIUM"},
	{needle: "exfiltrate", severity: "HIGH"},
	{needle: "paste your api key", severity: "HIGH"},
	{needle: "paste your token", severity: "HIGH"},
	{needle: "enter your password", severity: "HIGH"},
	{needle: "provide your credentials", severity: "HIGH"},
	{needle: "share your secret", severity: "HIGH"},
	{needle: "enter your api key", severity: "HIGH"},
	{needle: "give me your", severity: "MEDIUM", contextAware: true},
}

var contextAwareKeywords = []string{
	"ignore", "system", "hidden", "instruction", "secret", "override",
	"disregard", "forget", "pretend", "role", "assistant", "human",
	"execute", "command", "tool", "call", "run", "eval", "debug",
	"password", "token", "credential", "api_key", "api key",
	"exfiltrate", "send to", "post to", "upload",
	"hypothetically", "imagine", "suppose",
	"restrictions", "limitations", "safety", "guideline", "safeguard", "constraint",
}

func ScanMCPResponseForInjection(output string) []InjectionSignal {
	if output == "" {
		return nil
	}
	const maxScanBytes = 100_000
	if len(output) <= maxScanBytes*2 {
		return scanMCPResponseWindow(output, nil)
	}

	middleStart := len(output)/2 - maxScanBytes/2
	if middleStart < maxScanBytes {
		middleStart = maxScanBytes
	}
	if middleStart+maxScanBytes > len(output)-maxScanBytes {
		middleStart = len(output) - maxScanBytes - maxScanBytes/2
		if middleStart < maxScanBytes {
			middleStart = maxScanBytes
		}
	}

	windows := []string{
		output[:maxScanBytes],
		output[middleStart : middleStart+maxScanBytes],
		output[len(output)-maxScanBytes:],
	}
	seen := make(map[string]struct{}, len(injectionPatterns)+2)
	var signals []InjectionSignal
	for _, window := range windows {
		signals = append(signals, scanMCPResponseWindow(window, seen)...)
	}
	return signals
}

func HighestSeverity(signals []InjectionSignal) string {
	if len(signals) == 0 {
		return ""
	}
	highest := "LOW"
	for _, signal := range signals {
		switch signal.Severity {
		case "HIGH":
			return "HIGH"
		case "MEDIUM":
			if highest == "LOW" {
				highest = "MEDIUM"
			}
		}
	}
	return highest
}

func ScanMCPArgsForCredentials(toolInput map[string]interface{}) (bool, string) {
	return secretscan.ScanMCPArgsForCredentials(toolInput)
}

func ScanStringForCredentials(input string) (bool, string) {
	return secretscan.ScanStringForCredentials(input)
}

func hasContextKeyword(lower string, matchIdx, matchLen int) bool {
	windowStart := matchIdx - 200
	if windowStart < 0 {
		windowStart = 0
	}
	windowEnd := matchIdx + matchLen + 200
	if windowEnd > len(lower) {
		windowEnd = len(lower)
	}
	window := lower[windowStart:windowEnd]
	for _, keyword := range contextAwareKeywords {
		if strings.Contains(window, keyword) {
			return true
		}
	}
	return false
}

func extractContext(input string, index, maxLen int) string {
	start := index - maxLen/2
	if start < 0 {
		start = 0
	}
	end := start + maxLen
	if end > len(input) {
		end = len(input)
	}
	context := strings.ReplaceAll(input[start:end], "\n", " ")
	context = strings.ReplaceAll(context, "\r", " ")
	if start > 0 {
		context = "..." + context
	}
	if end < len(input) {
		context += "..."
	}
	return context
}

func checkSafetyNegationPhrase(lower string) (bool, string) {
	negationVerbs := []string{
		"bypass", "circumvent", "disable", "suppress", "remove",
		"work around", "get around", "override",
	}
	safetyObjects := []string{
		"safety", "safeguard", "restriction", "limitation", "guideline",
		"constraint", "control", "protect", "rule",
	}
	for _, verb := range negationVerbs {
		index := strings.Index(lower, verb)
		if index < 0 {
			continue
		}
		windowEnd := index + len(verb) + 100
		if windowEnd > len(lower) {
			windowEnd = len(lower)
		}
		window := lower[index:windowEnd]
		for _, object := range safetyObjects {
			if strings.Contains(window, object) {
				return true, "safety negation (" + verb + " " + object + ")"
			}
		}
	}
	return false, ""
}

func scanMCPResponseWindow(scanText string, seen map[string]struct{}) []InjectionSignal {
	lower := strings.ToLower(scanText)
	var signals []InjectionSignal
	addSignal := func(signal InjectionSignal) {
		if seen != nil {
			if _, ok := seen[signal.Pattern]; ok {
				return
			}
			seen[signal.Pattern] = struct{}{}
		}
		signals = append(signals, signal)
	}

	for _, zeroWidth := range []string{"\u200b", "\u200c", "\u200d", "\ufeff"} {
		if strings.Contains(scanText, zeroWidth) {
			addSignal(InjectionSignal{
				Pattern:  "zero-width character",
				Severity: "MEDIUM",
				Context:  "hidden text via zero-width Unicode characters",
			})
			break
		}
	}

	for _, pattern := range injectionPatterns {
		needle := strings.ToLower(pattern.needle)
		index := strings.Index(lower, needle)
		if index < 0 {
			continue
		}
		if pattern.contextAware && !hasContextKeyword(lower, index, len(needle)) {
			continue
		}
		addSignal(InjectionSignal{
			Pattern:  pattern.needle,
			Severity: pattern.severity,
			Context:  extractContext(lower, index, 60),
		})
	}

	if found, pattern := checkSafetyNegationPhrase(lower); found {
		addSignal(InjectionSignal{
			Pattern:  pattern,
			Severity: "MEDIUM",
			Context:  "attempt to negate safety controls",
		})
	}
	return signals
}
