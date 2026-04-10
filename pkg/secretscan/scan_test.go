package secretscan

import "testing"

func TestRedactMCPValueRedactsShortSensitiveKeyValues(t *testing.T) {
	got := RedactMCPValue("password", "123")
	if got != "[REDACTED:sensitive_key]" {
		t.Fatalf("RedactMCPValue(password, short) = %q", got)
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
