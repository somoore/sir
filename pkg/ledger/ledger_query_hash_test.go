package ledger

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/session"
)

func TestLedgerFilePermissions(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName: "Read",
		Verb:     "read_ref",
		Target:   "test.go",
		Decision: "allow",
		Reason:   "test",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(LedgerPath(projectRoot))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("ledger permissions = %o, want 600", perm)
	}
}

func TestLedgerPathLocation(t *testing.T) {
	projectRoot := "/some/project/path"
	path := LedgerPath(projectRoot)

	homeDir, _ := os.UserHomeDir()
	expectedPrefix := filepath.Join(homeDir, ".sir", "projects")

	if !strings.HasPrefix(path, expectedPrefix) {
		t.Errorf("ledger path %q should start with %q", path, expectedPrefix)
	}
	if !strings.HasSuffix(path, "ledger.jsonl") {
		t.Errorf("ledger path %q should end with ledger.jsonl", path)
	}

	hash := session.ProjectHash(projectRoot)
	if !strings.Contains(path, hash) {
		t.Errorf("ledger path %q should contain project hash %q", path, hash)
	}
}

func TestLedgerEntryTimestamp(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName: "Read",
		Verb:     "read_ref",
		Target:   "main.go",
		Decision: "allow",
		Reason:   "test",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	entries, _ := ReadAll(projectRoot)
	if entries[0].Timestamp.IsZero() {
		t.Error("entry timestamp should not be zero")
	}
}

// testContentHash computes SHA-256 hex of content for test assertions.
func testContentHash(content string) string {
	h := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", h)
}

// tamperLedger reads the ledger, applies mutFn to a specific entry, and writes it back.
// mutFn receives a pointer to the entry and modifies it in-place.
func tamperLedger(t *testing.T, projectRoot string, idx int, mutFn func(*Entry)) {
	t.Helper()
	ledgerPath := LedgerPath(projectRoot)
	data, err := os.ReadFile(ledgerPath)
	if err != nil {
		t.Fatalf("read ledger for tamper: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if idx >= len(lines) {
		t.Fatalf("tamper index %d out of bounds (have %d lines)", idx, len(lines))
	}
	var e Entry
	if err := json.Unmarshal([]byte(lines[idx]), &e); err != nil {
		t.Fatalf("unmarshal entry %d: %v", idx, err)
	}
	mutFn(&e)
	newData, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal tampered entry: %v", err)
	}
	lines[idx] = string(newData)
	if err := os.WriteFile(ledgerPath, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("write tampered ledger: %v", err)
	}
}

// appendTestEntry is a helper to add a simple allow entry.
func appendTestEntry(t *testing.T, projectRoot string, toolName, target string) {
	t.Helper()
	entry := &Entry{
		ToolName: toolName,
		Verb:     "execute_dry_run",
		Target:   target,
		Decision: "allow",
		Reason:   "within lease boundary",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatalf("append test entry: %v", err)
	}
}

func TestLedger_HashCoversContentHash(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      ".env",
		Sensitivity: "secret",
		Decision:    "ask",
		Reason:      "read sensitive file",
		ContentHash: testContentHash("original-content"),
		Preview:     "[REDACTED - secret-labeled content]",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	// Tamper with the ContentHash
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.ContentHash = testContentHash("tampered-content")
	})

	if _, err := Verify(projectRoot); err == nil {
		t.Error("expected Verify to fail after ContentHash tamper")
	}
}

func TestLedger_HashCoversPreview(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName: "Read",
		Verb:     "read_ref",
		Target:   "src/main.go",
		Decision: "allow",
		Reason:   "within lease boundary",
		Preview:  "package main",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	// Tamper with Preview
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.Preview = "injected content"
	})

	if _, err := Verify(projectRoot); err == nil {
		t.Error("expected Verify to fail after Preview tamper")
	}
}

func TestLedger_HashCoversSeverity(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName: "Bash",
		Verb:     "net_external",
		Target:   "evil.com",
		Decision: "deny",
		Reason:   "blocked",
		Severity: "HIGH",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	// Tamper: downgrade severity to avoid forensic alerting
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.Severity = "LOW"
	})

	if _, err := Verify(projectRoot); err == nil {
		t.Error("expected Verify to fail after Severity tamper")
	}
}

func TestLedger_HashCoversAlertType(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName:  "Bash",
		Verb:      "execute_dry_run",
		Target:    "npm install",
		Decision:  "deny",
		Reason:    "sentinel mutation",
		AlertType: "sentinel_mutation",
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	// Tamper: clear the alert type to hide the event
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.AlertType = ""
	})

	if _, err := Verify(projectRoot); err == nil {
		t.Error("expected Verify to fail after AlertType tamper")
	}
}

func TestLedger_HashCoversV2Fields(t *testing.T) {
	projectRoot := setupTestProject(t)

	entry := &Entry{
		ToolName:    "Bash",
		Verb:        "execute_dry_run",
		Target:      "sir restore",
		Decision:    "deny",
		Reason:      "hook tamper restored",
		AlertType:   "hook_tamper",
		Evidence:    "{\"removed\":\"[REDACTED:github_pat]\"}",
		Agent:       "codex",
		DiffSummary: "removed PreToolUse hook",
		Restored:    true,
	}
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.Evidence = ""
	})
	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("expected Verify to fail after Evidence tamper")
	}

	projectRoot = setupTestProject(t)
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.Agent = "claude"
	})
	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("expected Verify to fail after Agent tamper")
	}

	projectRoot = setupTestProject(t)
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.DiffSummary = "removed PostToolUse hook"
	})
	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("expected Verify to fail after DiffSummary tamper")
	}

	projectRoot = setupTestProject(t)
	if err := Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}
	tamperLedger(t, projectRoot, 0, func(e *Entry) {
		e.Restored = false
	})
	if _, err := Verify(projectRoot); err == nil {
		t.Fatal("expected Verify to fail after Restored tamper")
	}
}

func TestLedger_UnmodifiedChainValid(t *testing.T) {
	projectRoot := setupTestProject(t)

	for i := 0; i < 3; i++ {
		appendTestEntry(t, projectRoot, "Bash", fmt.Sprintf("make target-%d", i))
	}

	count, err := Verify(projectRoot)
	if err != nil {
		t.Fatalf("Verify failed on unmodified chain: %v", err)
	}
	if count != 3 {
		t.Errorf("verified %d entries, want 3", count)
	}
}

func TestGetLastEntry(t *testing.T) {
	projectRoot := setupTestProject(t)

	// Empty ledger
	e, err := GetLastEntry(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if e != nil {
		t.Error("expected nil for empty ledger")
	}

	// Add entries
	for i := 0; i < 3; i++ {
		appendTestEntry(t, projectRoot, "Bash", fmt.Sprintf("cmd-%d", i))
	}

	e, err = GetLastEntry(projectRoot)
	if err != nil {
		t.Fatal(err)
	}
	if e == nil {
		t.Fatal("expected non-nil entry")
	}
	if e.Index != 2 {
		t.Errorf("last entry index = %d, want 2", e.Index)
	}
	if e.Target != "cmd-2" {
		t.Errorf("last entry target = %q, want cmd-2", e.Target)
	}
}

func TestGetEntryByIndex(t *testing.T) {
	projectRoot := setupTestProject(t)

	for i := 0; i < 5; i++ {
		appendTestEntry(t, projectRoot, "Bash", fmt.Sprintf("cmd-%d", i))
	}

	// Valid index
	e, _, err := GetEntryByIndex(projectRoot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if e == nil {
		t.Fatal("expected non-nil entry")
	}
	if e.Target != "cmd-2" {
		t.Errorf("entry target = %q, want cmd-2", e.Target)
	}

	// Out of range
	_, _, err = GetEntryByIndex(projectRoot, 10)
	if err == nil {
		t.Error("expected error for out of range index")
	}

	// Negative index
	_, _, err = GetEntryByIndex(projectRoot, -1)
	if err == nil {
		t.Error("expected error for negative index")
	}
}

func TestFindCausalSecretRead(t *testing.T) {
	entries := []Entry{
		{Index: 0, ToolName: "Read", Verb: "read_ref", Target: "main.go", Decision: "allow"},
		{Index: 1, ToolName: "Read", Verb: "read_ref", Target: ".env", Sensitivity: "secret", Decision: "ask"},
		{Index: 2, ToolName: "Read", Verb: "read_ref", Target: "config.go", Decision: "allow"},
		{Index: 3, ToolName: "Bash", Verb: "net_external", Target: "https://evil.com", Decision: "deny"},
	}

	// From the deny entry, find the causal secret read
	causal := FindCausalSecretRead(entries, 3)
	if causal == nil {
		t.Fatal("expected to find causal secret read")
	}
	if causal.Index != 1 {
		t.Errorf("causal index = %d, want 1", causal.Index)
	}
	if causal.Target != ".env" {
		t.Errorf("causal target = %q, want .env", causal.Target)
	}

	// No causal read before first entry
	causal = FindCausalSecretRead(entries, 0)
	if causal != nil {
		t.Error("expected no causal read before index 0")
	}
}

func TestFindCausalSecretRead_EnvRead(t *testing.T) {
	entries := []Entry{
		{Index: 0, ToolName: "Bash", Verb: "env_read", Target: "env", Decision: "ask"},
		{Index: 1, ToolName: "Bash", Verb: "net_external", Target: "https://evil.com", Decision: "deny"},
	}

	causal := FindCausalSecretRead(entries, 1)
	if causal == nil {
		t.Fatal("expected to find causal env_read")
	}
	if causal.Verb != "env_read" {
		t.Errorf("causal verb = %q, want env_read", causal.Verb)
	}
}

func TestFindCausalSecretRead_NoSecret(t *testing.T) {
	entries := []Entry{
		{Index: 0, ToolName: "Read", Verb: "read_ref", Target: "main.go", Decision: "allow"},
		{Index: 1, ToolName: "Bash", Verb: "execute_dry_run", Target: "make build", Decision: "allow"},
	}

	causal := FindCausalSecretRead(entries, 1)
	if causal != nil {
		t.Error("expected no causal secret read in a clean session")
	}
}

func TestFindRelatedEntries(t *testing.T) {
	entries := []Entry{
		{Index: 0, ToolName: "Read", Verb: "read_ref", Target: ".env", Sensitivity: "secret", Decision: "ask"},
		{Index: 1, ToolName: "Read", Verb: "read_ref", Target: ".aws/credentials", Sensitivity: "secret", Decision: "ask"},
		{Index: 2, ToolName: "Read", Verb: "read_ref", Target: "main.go", Decision: "allow"},
		{Index: 3, ToolName: "Bash", Verb: "net_external", Target: "https://evil.com", Decision: "deny"},
	}

	related := FindRelatedEntries(entries, 3)
	if len(related) < 1 {
		t.Fatal("expected at least one related entry")
	}

	// Both secret reads should be in related entries
	foundEnv := false
	foundAws := false
	for _, r := range related {
		if r.Target == ".env" {
			foundEnv = true
		}
		if r.Target == ".aws/credentials" {
			foundAws = true
		}
	}
	if !foundEnv {
		t.Error("expected .env in related entries")
	}
	if !foundAws {
		t.Error("expected .aws/credentials in related entries")
	}
}

func TestComputeHash_NoCollisionViaTargetInjection(t *testing.T) {
	base := Entry{
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Index:    0,
		ToolName: "Read",
		Verb:     "read_ref",
		Decision: "allow",
		Reason:   "bar",
	}
	a := base
	a.Target = "foo"
	b := base
	b.Target = "foo|"
	c := base
	c.Target = "foo|baz|"
	d := base
	d.Target = "foo|bar"
	d.Reason = ""

	ha := computeHash(&a)
	hb := computeHash(&b)
	hc := computeHash(&c)
	hd := computeHash(&d)

	hashes := map[string]string{"a": ha, "b": hb, "c": hc, "d": hd}
	seen := map[string]string{}
	for name, h := range hashes {
		if prev, ok := seen[h]; ok {
			t.Errorf("hash collision between %q and %q: %s", prev, name, h)
		}
		seen[h] = name
	}
}

func TestComputeHash_NoCollisionViaReasonInjection(t *testing.T) {
	base := Entry{
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Index:    1,
		ToolName: "Bash",
		Verb:     "net_external",
		Target:   "evil.com",
		Decision: "deny",
	}
	a := base
	a.Reason = "blocked"
	a.ContentHash = "abc"
	b := base
	b.Reason = "blocked|abc"
	b.ContentHash = ""
	c := base
	c.Reason = "blocked|"
	c.ContentHash = "|abc"

	ha := computeHash(&a)
	hb := computeHash(&b)
	hc := computeHash(&c)
	if ha == hb || ha == hc || hb == hc {
		t.Errorf("reason-injection hash collision: ha=%s hb=%s hc=%s", ha, hb, hc)
	}
}

func TestComputeHash_LengthPrefixCovered(t *testing.T) {
	base := Entry{
		PrevHash: "0000000000000000000000000000000000000000000000000000000000000000",
		Index:    2,
		ToolName: "Bash",
		Verb:     "execute_dry_run",
		Target:   "make",
		Decision: "allow",
		Reason:   "ok",
	}
	a := base
	a.Severity = ""
	a.AlertType = "A"
	b := base
	b.Severity = "A"
	b.AlertType = ""
	if computeHash(&a) == computeHash(&b) {
		t.Error("length prefix not covering empty-vs-nonempty shift")
	}

	// Also verify that extending one field by one char and shortening
	// the next by the same amount produces different hashes.
	c := base
	c.Trust = "verified"
	c.Provenance = "user"
	d := base
	d.Trust = "verifiedu"
	d.Provenance = "ser"
	if computeHash(&c) == computeHash(&d) {
		t.Error("length prefix not preventing boundary shift collision")
	}
}

func TestComputeHash_DeterministicForSameInput(t *testing.T) {
	e := Entry{
		PrevHash:    "abc123",
		Index:       5,
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      ".env",
		Sensitivity: "secret",
		Trust:       "trusted",
		Provenance:  "user",
		Decision:    "ask",
		Reason:      "sensitive",
		ContentHash: "deadbeef",
		Preview:     "[REDACTED - secret-labeled content]",
		Severity:    "HIGH",
		AlertType:   "none",
	}
	h1 := computeHash(&e)
	h2 := computeHash(&e)
	if h1 != h2 {
		t.Errorf("computeHash not deterministic: %s vs %s", h1, h2)
	}
}

func TestFindRelatedEntries_AllowNonSensitive(t *testing.T) {
	entries := []Entry{
		{Index: 0, ToolName: "Read", Verb: "read_ref", Target: "main.go", Decision: "allow"},
	}

	related := FindRelatedEntries(entries, 0)
	if len(related) != 0 {
		t.Errorf("expected no related entries for simple allow, got %d", len(related))
	}
}
