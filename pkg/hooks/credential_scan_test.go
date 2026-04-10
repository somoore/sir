package hooks

import (
	"strings"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
)

func hasPattern(matches []CredentialMatch, name string) bool {
	for _, m := range matches {
		if m.PatternName == name {
			return true
		}
	}
	return false
}

func TestScanOutput_AWSAccessKey(t *testing.T) {
	out := "aws_access_key_id = " + testsecrets.AWSAccessKey() + "\naws_secret_access_key = EXAMPLE_AWS_SECRET"
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "aws_access_key") {
		t.Errorf("expected aws_access_key match, got %+v", matches)
	}
}

func TestScanOutput_GitHubPAT(t *testing.T) {
	out := "GITHUB_TOKEN=" + testsecrets.GitHubPAT()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "github_pat") {
		t.Errorf("expected github_pat match, got %+v", matches)
	}
}

func TestScanOutput_GitHubFineGrainedPAT(t *testing.T) {
	out := "token: " + testsecrets.GitHubFineGrainedPAT()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "github_fine_grained_pat") {
		t.Errorf("expected github_fine_grained_pat match, got %+v", matches)
	}
}

func TestScanOutput_SlackBotToken(t *testing.T) {
	out := "SLACK_BOT_TOKEN=" + testsecrets.SlackBotToken()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "slack_bot_token") {
		t.Errorf("expected slack_bot_token match, got %+v", matches)
	}
}

func TestScanOutput_StripeKey(t *testing.T) {
	out := "stripe.api_key = " + testsecrets.StripeLiveKey()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "stripe_secret_key") {
		t.Errorf("expected stripe_secret_key match, got %+v", matches)
	}
}

func TestScanOutput_GoogleAPIKey(t *testing.T) {
	out := "GOOGLE_API_KEY=" + testsecrets.GoogleAPIKey()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "google_api_key") {
		t.Errorf("expected google_api_key match, got %+v", matches)
	}
}

func TestScanOutput_PrivateKeyHeader(t *testing.T) {
	out := testsecrets.RSAHeader() + "\nMIIEpAIBAAK..."
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "private_key_header") {
		t.Errorf("expected private_key_header match, got %+v", matches)
	}
}

func TestScanOutput_PrivateKeyOpenSSH(t *testing.T) {
	out := testsecrets.OpenSSHHeader() + "\nb3BlbnNzaC1rZXkt..."
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "private_key_header") {
		t.Errorf("expected private_key_header (openssh) match, got %+v", matches)
	}
}

func TestScanOutput_JWT(t *testing.T) {
	out := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "jwt") {
		t.Errorf("expected jwt match, got %+v", matches)
	}
}

func TestScanOutput_SSNValid(t *testing.T) {
	out := "Employee SSN: 123-45-6789 (please secure)"
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "ssn") {
		t.Errorf("expected ssn match, got %+v", matches)
	}
}

func TestScanOutput_CreditCardValidVisa(t *testing.T) {
	out := "Card on file: 4532015112830366"
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "credit_card") {
		t.Errorf("expected credit_card match, got %+v", matches)
	}
}

func TestScanOutput_OpenAIKey(t *testing.T) {
	out := "OPENAI_API_KEY=" + testsecrets.OpenAIProjectKey()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "openai_api_key") {
		t.Errorf("expected openai_api_key match, got %+v", matches)
	}
}

// False-positive tests

func TestScanOutput_NormalGoCode(t *testing.T) {
	out := `package main

import "fmt"

func main() {
	x := 42
	fmt.Println("hello world", x)
}`
	matches := ScanOutputForCredentials(out)
	if len(matches) > 0 {
		t.Errorf("expected no matches for normal Go code, got %+v", matches)
	}
}

func TestScanOutput_InvalidSSNArea000(t *testing.T) {
	out := "ID: 000-12-3456"
	matches := ScanOutputForCredentials(out)
	if hasPattern(matches, "ssn") {
		t.Errorf("expected no ssn match for area 000, got %+v", matches)
	}
}

func TestScanOutput_InvalidSSNArea666(t *testing.T) {
	out := "Ref: 666-12-3456"
	matches := ScanOutputForCredentials(out)
	if hasPattern(matches, "ssn") {
		t.Errorf("expected no ssn match for area 666, got %+v", matches)
	}
}

func TestScanOutput_InvalidSSNArea900(t *testing.T) {
	out := "Code: 900-12-3456"
	matches := ScanOutputForCredentials(out)
	if hasPattern(matches, "ssn") {
		t.Errorf("expected no ssn match for area 9xx, got %+v", matches)
	}
}

func TestScanOutput_CreditCardFailsLuhn(t *testing.T) {
	out := "Number: 1234567890123456"
	matches := ScanOutputForCredentials(out)
	if hasPattern(matches, "credit_card") {
		t.Errorf("expected no credit_card match for invalid Luhn, got %+v", matches)
	}
}

func TestScanOutput_UUIDNotHighEntropy(t *testing.T) {
	out := "request-id: 550e8400-e29b-41d4-a716-446655440000"
	matches := ScanOutputForCredentials(out)
	for _, m := range matches {
		if m.PatternName == "high_entropy_token" {
			t.Errorf("expected UUID not flagged as high entropy, got %+v", matches)
		}
	}
}

// Validator tests

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"valid_visa", "4532015112830366", true},
		{"valid_mastercard", "5425233430109903", true},
		{"valid_amex", "378282246310005", true},
		{"invalid_checksum", "1234567890123456", false},
		{"too_short", "123456", false},
		{"too_long", "12345678901234567890", false},
		{"valid_with_spaces", "4532 0151 1283 0366", true},
		{"valid_with_dashes", "4532-0151-1283-0366", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateLuhn(tt.in); got != tt.want {
				t.Errorf("validateLuhn(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestValidateSSN(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"123-45-6789", true},
		{"001-01-0001", true},
		{"000-12-3456", false},
		{"666-12-3456", false},
		{"900-12-3456", false},
		{"999-12-3456", false},
		{"123-00-1234", false},
		{"123-45-0000", false},
		{"12345-6789", false}, // wrong format
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := validateSSN(tt.in); got != tt.want {
				t.Errorf("validateSSN(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// Entropy tests

func TestShannonEntropy_RandomHex(t *testing.T) {
	s := "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0"
	e := shannonEntropy(s)
	if e < 3.5 {
		t.Errorf("expected high entropy for random hex, got %f", e)
	}
}

func TestShannonEntropy_Repetitive(t *testing.T) {
	if e := shannonEntropy("aaaaaaaaaaaaaaaa"); e != 0 {
		t.Errorf("expected 0 entropy for repetitive string, got %f", e)
	}
}

func TestShannonEntropy_Empty(t *testing.T) {
	if e := shannonEntropy(""); e != 0 {
		t.Errorf("expected 0 entropy for empty string, got %f", e)
	}
}

func TestIsHighEntropyString_Random40Char(t *testing.T) {
	// 40-char random base64-like string
	s := "Xz8KqLm3Np9Rt2Vw5Ya7Bc4Df6Gh1Jk0Lm8Np2Qs"
	if !isHighEntropyString(s) {
		t.Errorf("expected high entropy string detection")
	}
}

func TestIsHighEntropyString_TooShort(t *testing.T) {
	if isHighEntropyString("abc123") {
		t.Errorf("expected false for short string")
	}
}

func TestIsHighEntropyString_HasSpaces(t *testing.T) {
	if isHighEntropyString("this is a normal english sentence with words") {
		t.Errorf("expected false for string with spaces")
	}
}

// Integration tests

func TestScanOutput_MultiplePatterns(t *testing.T) {
	out := "aws_key = " + testsecrets.AWSAccessKey() + "\n" +
		"github = " + testsecrets.GitHubPAT() + "\n" +
		"key = " + testsecrets.RSAHeader()
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "aws_access_key") {
		t.Errorf("missing aws_access_key in %+v", matches)
	}
	if !hasPattern(matches, "github_pat") {
		t.Errorf("missing github_pat in %+v", matches)
	}
	if !hasPattern(matches, "private_key_header") {
		t.Errorf("missing private_key_header in %+v", matches)
	}
}

func TestScanOutput_EmptyOutput(t *testing.T) {
	if matches := ScanOutputForCredentials(""); len(matches) != 0 {
		t.Errorf("expected no matches for empty input, got %+v", matches)
	}
}

func TestScanOutput_DeduplicatesPatterns(t *testing.T) {
	aws := testsecrets.AWSAccessKey()
	out := "key1=" + aws + " key2=" + aws[:len(aws)-1] + "2 key3=" + aws[:len(aws)-1] + "3"
	matches := ScanOutputForCredentials(out)
	count := 0
	for _, m := range matches {
		if m.PatternName == "aws_access_key" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 aws_access_key match (deduplicated), got %d", count)
	}
}

func TestScanOutput_LargePayloadTailDetection(t *testing.T) {
	// Build a 300KB string with a credential at position 250KB (in the tail window)
	filler := strings.Repeat("x", 250*1024)
	tail := strings.Repeat("y", 50*1024-30)
	out := filler + testsecrets.AWSAccessKey() + tail
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "aws_access_key") {
		t.Errorf("expected detection in tail window of large payload, got %+v", matches)
	}
}

func TestScanOutput_LargePayloadHeadDetection(t *testing.T) {
	// Credential at position 1KB (in the head window)
	head := strings.Repeat("x", 1024)
	tail := strings.Repeat("y", 300*1024)
	out := head + testsecrets.AWSAccessKey() + tail
	matches := ScanOutputForCredentials(out)
	if !hasPattern(matches, "aws_access_key") {
		t.Errorf("expected detection in head window of large payload, got %+v", matches)
	}
}
