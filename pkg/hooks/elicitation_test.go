package hooks

import (
	"strings"
	"testing"
)

// ElicitationWarning represents a warning about a suspicious elicitation prompt.
type ElicitationWarning struct {
	Severity string // "high", "medium"
	Detail   string
}

// ScanElicitation checks if a prompt message is attempting to harvest credentials.
// This fires when Claude Code sends an Elicitation (user prompt) tool call.
func ScanElicitation(message string) *ElicitationWarning {
	if message == "" {
		return nil
	}

	lower := strings.ToLower(message)

	// High severity: direct credential harvest attempts
	highPatterns := []string{
		"paste your",
		"enter your api key",
		"enter your token",
		"enter your password",
		"enter your secret",
		"provide your credentials",
		"share your key",
		"give me your",
		"send me your",
		"type your password",
		"type your token",
		"type your api key",
	}
	for _, p := range highPatterns {
		if strings.Contains(lower, p) {
			// Check if it's about credentials, not generic input
			credWords := []string{
				"key", "token", "password", "secret", "credential",
				"api", "auth", "github", "aws", "openai",
			}
			for _, cw := range credWords {
				if strings.Contains(lower, cw) {
					return &ElicitationWarning{
						Severity: "high",
						Detail:   "credential harvest attempt detected: " + p,
					}
				}
			}
		}
	}

	// Medium severity: social engineering patterns
	mediumPatterns := []string{
		"session expired",
		"authentication required",
		"re-authenticate",
		"verify your identity",
		"confirm your access",
	}
	for _, p := range mediumPatterns {
		if strings.Contains(lower, p) {
			return &ElicitationWarning{
				Severity: "medium",
				Detail:   "social engineering pattern detected: " + p,
			}
		}
	}

	return nil
}

// --- Tests ---

func TestElicitation_CredentialHarvest(t *testing.T) {
	warning := ScanElicitation("Please paste your GitHub token here to continue")
	if warning == nil {
		t.Fatal("expected warning for credential harvest prompt")
	}
	if warning.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", warning.Severity)
	}
	if !strings.Contains(warning.Detail, "credential harvest") {
		t.Errorf("expected detail to mention credential harvest, got %q", warning.Detail)
	}
}

func TestElicitation_LegitimatePrompt(t *testing.T) {
	warning := ScanElicitation("Enter the project name")
	if warning != nil {
		t.Errorf("expected no warning for legitimate prompt, got: %v", warning)
	}
}

func TestElicitation_SessionExpired(t *testing.T) {
	warning := ScanElicitation("Session expired. Please paste your API key to re-authenticate.")
	if warning == nil {
		t.Fatal("expected warning for session expired + credential request")
	}
	// Could be high (paste your + key) or medium (session expired) — either is acceptable
	if warning.Severity != "high" && warning.Severity != "medium" {
		t.Errorf("expected severity 'high' or 'medium', got %q", warning.Severity)
	}
}

func TestElicitation_AuthRequired(t *testing.T) {
	warning := ScanElicitation("Authentication required to access this resource.")
	if warning == nil {
		t.Fatal("expected warning for 'authentication required' pattern")
	}
	if warning.Severity != "medium" {
		t.Errorf("expected severity 'medium', got %q", warning.Severity)
	}
}

func TestElicitation_Empty(t *testing.T) {
	warning := ScanElicitation("")
	if warning != nil {
		t.Errorf("expected no warning for empty input, got: %v", warning)
	}
}
