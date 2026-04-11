package secretscan

import (
	"strings"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
)

func hasPattern(matches []CredentialMatch, name string) bool {
	for _, match := range matches {
		if match.PatternName == name {
			return true
		}
	}
	return false
}

func TestScanOutputForCredentials_DetectsStructuredSecrets(t *testing.T) {
	matches := ScanOutputForCredentials("OPENAI_API_KEY=" + testsecrets.OpenAIProjectKey())
	if !hasPattern(matches, "openai_api_key") {
		t.Fatalf("expected openai_api_key match, got %+v", matches)
	}
}

func TestRedactStructuredText_RedactsStructuredAndHighEntropyTokens(t *testing.T) {
	highEntropy := "Zx8Qm1Nf7Vb4Lc2Kt9Pw5Hs3Jd6Rg8Ty0Ua1We2Ri3Po4Nk7"
	got := RedactStructuredText("token=" + testsecrets.OpenAIProjectKey() + "\n" + highEntropy)
	for _, want := range []string{"[REDACTED:openai_api_key]", "[REDACTED:high_entropy_token]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("redacted output missing %q:\n%s", want, got)
		}
	}
}

func TestRedactMCPValueRedactsShortSensitiveKeyValues(t *testing.T) {
	got := RedactMCPValue("password", "123")
	if got != "[REDACTED:sensitive_key]" {
		t.Fatalf("RedactMCPValue(password, short) = %q", got)
	}
}

func TestRedactMCPValue_PrefersStructuredRedactionOverSensitiveKeyFallback(t *testing.T) {
	got := RedactMCPValue("password", testsecrets.OpenAIProjectKey())
	if got != "[REDACTED:openai_api_key]" {
		t.Fatalf("RedactMCPValue(password, structured) = %q", got)
	}
}

func TestScanMCPArgsForCredentialsMatchesShortSensitiveKeyValues(t *testing.T) {
	found, hint := ScanMCPArgsForCredentials(map[string]interface{}{"password": "123"})
	if !found {
		t.Fatal("expected sensitive key name with short value to trigger credential scan")
	}
	if hint == "" {
		t.Fatal("expected credential scan hint for short sensitive key value")
	}
}

func TestScanStringForCredentials_DetectsSensitiveValueHints(t *testing.T) {
	found, hint := ScanStringForCredentials("Authorization: Bearer abc123")
	if !found {
		t.Fatal("expected bearer token to trigger credential scan")
	}
	if !strings.Contains(hint, "Bearer ") {
		t.Fatalf("expected Bearer hint, got %q", hint)
	}
}
