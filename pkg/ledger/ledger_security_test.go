package ledger

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/somoore/sir/internal/testsecrets"
)

func TestLedger_VerifyLegacyEntriesAfterUpgrade(t *testing.T) {
	projectRoot := setupTestProject(t)
	genesis := strings.Repeat("0", 64)
	legacy := Entry{
		Index:       0,
		Timestamp:   time.Unix(1_700_000_000, 0).UTC(),
		PrevHash:    genesis,
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      ".env",
		Sensitivity: "secret",
		Decision:    "ask",
		Reason:      "legacy entry",
	}
	legacy.EntryHash = computeHash(&legacy)
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy entry: %v", err)
	}
	if err := os.WriteFile(LedgerPath(projectRoot), append(data, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy ledger: %v", err)
	}

	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("verify legacy ledger: %v", err)
	}
	if count != 1 {
		t.Fatalf("verified %d entries, want 1", count)
	}

	newEntry := &Entry{
		ToolName:  "mcp__evil__tool",
		Verb:      "mcp_unapproved",
		Target:    "evil-server",
		Decision:  "deny",
		Reason:    "unapproved MCP",
		Evidence:  "{\"apiKey\":\"[REDACTED:aws_access_key]\"}",
		Agent:     "gemini",
		AlertType: "hook_tamper",
	}
	if err := Append(projectRoot, newEntry); err != nil {
		t.Fatalf("append upgraded entry: %v", err)
	}

	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read mixed ledger: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].HashVersion != 0 {
		t.Fatalf("legacy entry hash_version = %d, want omitted/0", entries[0].HashVersion)
	}
	if entries[1].HashVersion != currentHashVersion {
		t.Fatalf("new entry hash_version = %d, want %d", entries[1].HashVersion, currentHashVersion)
	}

	count, err = Verify(projectRoot)
	if err != nil {
		t.Fatalf("verify mixed ledger: %v", err)
	}
	if count != 2 {
		t.Fatalf("verified %d entries, want 2", count)
	}
}

func TestHashChainDetectsTampering(t *testing.T) {
	projectRoot := setupTestProject(t)

	for i := 0; i < 3; i++ {
		entry := &Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "ls",
			Decision: "allow",
			Reason:   "within lease boundary",
		}
		if err := Append(projectRoot, entry); err != nil {
			t.Fatal(err)
		}
	}

	// Tamper with the ledger file
	ledgerPath := LedgerPath(projectRoot)
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d", len(lines))
	}

	// Modify the second entry's decision
	var entry Entry
	if err := json.Unmarshal([]byte(lines[1]), &entry); err != nil {
		t.Fatal(err)
	}
	entry.Decision = "deny" // tamper
	tampered, _ := json.Marshal(entry)
	lines[1] = string(tampered)
	os.WriteFile(ledgerPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600)

	// Verification should detect tampering
	_, err = Verify(projectRoot)
	if err == nil {
		t.Error("expected verification to fail after tampering")
	}
}

func TestEmptyLedgerVerification(t *testing.T) {
	projectRoot := setupTestProject(t)
	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("verify empty ledger: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 entries, got %d", count)
	}
}

func TestReadAllFreshProjectWithoutStateDir(t *testing.T) {
	projectRoot := t.TempDir()

	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll fresh project: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("ReadAll fresh project returned %d entries, want 0", len(entries))
	}

	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("Verify fresh project: %v", err)
	}
	if count != 0 {
		t.Fatalf("Verify fresh project count = %d, want 0", count)
	}
}

func TestLedgerNeverStoresSecretContent(t *testing.T) {
	projectRoot := setupTestProject(t)

	secretContent := "AWS_SECRET_ACCESS_KEY=EXAMPLE_AWS_SECRET_ACCESS_KEY"
	contentHash := testContentHash(secretContent)

	entry := &Entry{
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      ".env",
		Sensitivity: "secret",
		Trust:       "trusted",
		Provenance:  "user",
		Decision:    "ask",
		Reason:      "read sensitive file: .env (sensitivity: secret)",
		ContentHash: contentHash,
		Preview:     RedactPreview(secretContent, true),
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	// Read raw file to check for leaked secrets
	rawData, _ := os.ReadFile(LedgerPath(projectRoot))
	raw := string(rawData)

	// Actual secret value must NOT appear
	if strings.Contains(raw, "EXAMPLE_AWS_SECRET_ACCESS_KEY") {
		t.Error("SECURITY: ledger contains actual secret key material")
	}
	if strings.Contains(raw, "AWS_SECRET_ACCESS_KEY") {
		t.Error("SECURITY: ledger contains secret variable name from content")
	}

	// Path SHOULD be present
	if !strings.Contains(raw, ".env") {
		t.Error("ledger should contain the file path")
	}

	// Content hash SHOULD be present
	if !strings.Contains(raw, contentHash) {
		t.Error("ledger should contain the content hash")
	}

	// Preview should be redacted
	entries, _ := ReadAll(projectRoot)
	if entries[0].Preview != "[REDACTED - secret-labeled content]" {
		t.Errorf("preview should be redacted, got %q", entries[0].Preview)
	}
}

func TestLedgerPathOnlyStorageForSensitiveFiles(t *testing.T) {
	projectRoot := setupTestProject(t)

	sensitiveFiles := []string{".env", ".env.local", ".aws/credentials", ".ssh/id_rsa"}
	secretContents := []string{
		"DB_PASSWORD=hunter2",
		"API_KEY=example-api-key",
		"aws_secret_access_key=example-secret",
		testsecrets.RSAHeader(),
	}

	for i, f := range sensitiveFiles {
		entry := &Entry{
			ToolName:    "Read",
			Verb:        "read_ref",
			Target:      f,
			Sensitivity: "secret",
			Decision:    "ask",
			Reason:      "read sensitive file: " + f,
			ContentHash: testContentHash(secretContents[i]),
			Preview:     RedactPreview(secretContents[i], true),
		}
		if err := Append(projectRoot, entry); err != nil {
			t.Fatalf("append for %s: %v", f, err)
		}
	}

	rawData, _ := os.ReadFile(LedgerPath(projectRoot))
	raw := string(rawData)

	// None of these secret fragments should appear in the ledger
	secretFragments := []string{
		"hunter2", "example-api-key", "example-secret",
		"BEGIN RSA PRIVATE KEY",
		"DB_PASSWORD", "API_KEY", "aws_secret_access_key",
	}
	for _, fragment := range secretFragments {
		if strings.Contains(raw, fragment) {
			t.Errorf("SECURITY: ledger contains secret fragment %q", fragment)
		}
	}

	// All file paths should be present
	for _, f := range sensitiveFiles {
		if !strings.Contains(raw, f) {
			t.Errorf("ledger should contain path %q", f)
		}
	}
}

func TestLedgerAppendSanitizesStructuredFields(t *testing.T) {
	projectRoot := setupTestProject(t)
	rawToken := testsecrets.OpenAIKey()

	entry := &Entry{
		ToolName:    "Bash",
		Verb:        "net_external",
		Target:      "https://example.com",
		Decision:    "deny",
		Reason:      "secret token " + rawToken + " should never persist",
		Evidence:    `{"api_key":"` + rawToken + `","password":"hunter2"}`,
		DiffSummary: "leaked bearer token Bearer abcdef123456",
		Preview:     "preview " + rawToken,
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatalf("Append: %v", err)
	}

	raw, err := os.ReadFile(LedgerPath(projectRoot))
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	for _, secret := range []string{rawToken, "hunter2", "Bearer abcdef123456"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("SECURITY: ledger contains raw secret fragment %q", secret)
		}
	}

	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ReadAll len = %d, want 1", len(entries))
	}
	if entries[0].Reason == "secret token "+rawToken+" should never persist" {
		t.Fatal("ledger reason was not sanitized")
	}
	if entries[0].Evidence == `{"api_key":"`+rawToken+`","password":"hunter2"}` {
		t.Fatal("ledger evidence was not sanitized")
	}
	if entries[0].DiffSummary == "leaked bearer token Bearer abcdef123456" {
		t.Fatal("ledger diff summary was not sanitized")
	}
}

func TestRedactPreview(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		isSecret bool
		expected string
	}{
		{
			name:     "secret content is redacted",
			content:  "AWS_KEY=supersecret",
			isSecret: true,
			expected: "[REDACTED - secret-labeled content]",
		},
		{
			name:     "short non-secret shown in full",
			content:  "package main",
			isSecret: false,
			expected: "package main",
		},
		{
			name:     "long non-secret is truncated at 80 chars",
			content:  strings.Repeat("x", 100),
			isSecret: false,
			expected: strings.Repeat("x", 80) + "...",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := RedactPreview(tc.content, tc.isSecret)
			if got != tc.expected {
				t.Errorf("RedactPreview(%q, %v) = %q, want %q",
					tc.content, tc.isSecret, got, tc.expected)
			}
		})
	}
}

func TestSequentialAppendsMaintainIndices(t *testing.T) {
	projectRoot := setupTestProject(t)

	for i := 0; i < 10; i++ {
		entry := &Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "make build",
			Decision: "allow",
			Reason:   "within lease boundary",
		}
		if err := Append(projectRoot, entry); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	entries, err := ReadAll(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 {
		t.Fatalf("expected 10 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Index != i {
			t.Errorf("entry %d has index %d", i, e.Index)
		}
	}

	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if count != 10 {
		t.Errorf("verified %d entries, want 10", count)
	}
}
