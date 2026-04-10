package hooks

import "github.com/somoore/sir/pkg/secretscan"

// CredentialMatch describes a detected credential pattern.
// Never stores the actual matched value.
type CredentialMatch = secretscan.CredentialMatch

// ScanOutputForCredentials scans tool output text for structured secret
// patterns. This is a thin wrapper over the shared scanner so the hooks
// package keeps its existing public surface.
func ScanOutputForCredentials(output string) []CredentialMatch {
	return secretscan.ScanOutputForCredentials(output)
}

func validateLuhn(s string) bool {
	return secretscan.ValidateLuhn(s)
}

func validateSSN(s string) bool {
	return secretscan.ValidateSSN(s)
}

func shannonEntropy(s string) float64 {
	return secretscan.ShannonEntropy(s)
}

func isHighEntropyString(s string) bool {
	return secretscan.IsHighEntropyString(s)
}
