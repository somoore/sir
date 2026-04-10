package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
)

// -------------------------------------------------------------------
// cmdLog tests
// -------------------------------------------------------------------

func TestCmdLedger_EmptyLedger(t *testing.T) {
	env := newTestEnv(t)
	// Should not panic
	cmdLog(env.projectRoot, false)
}

func TestCmdLedger_WithEntries(t *testing.T) {
	env := newTestEnv(t)

	// Add some entries
	for i := 0; i < 3; i++ {
		if err := ledger.Append(env.projectRoot, &ledger.Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "go test ./...",
			Decision: "allow",
			Reason:   "standard dev command",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// Should not panic
	cmdLog(env.projectRoot, false)
}

func TestCmdLedger_VerifyIntact(t *testing.T) {
	env := newTestEnv(t)

	// Add entries with proper hash chain
	for i := 0; i < 3; i++ {
		if err := ledger.Append(env.projectRoot, &ledger.Entry{
			ToolName: "Read",
			Verb:     "read_ref",
			Target:   "main.go",
			Decision: "allow",
			Reason:   "normal file",
		}); err != nil {
			t.Fatal(err)
		}
	}

	// verify should succeed
	cmdLog(env.projectRoot, true)
}

func TestCmdLedger_VerifyBrokenChain(t *testing.T) {
	env := newTestEnv(t)

	// Add entries
	for i := 0; i < 3; i++ {
		ledger.Append(env.projectRoot, &ledger.Entry{
			ToolName: "Read",
			Verb:     "read_ref",
			Target:   "main.go",
			Decision: "allow",
			Reason:   "test",
		})
	}

	// Corrupt the ledger by modifying the file
	ledgerPath := ledger.LedgerPath(env.projectRoot)
	data, _ := os.ReadFile(ledgerPath)
	// Replace first character of a hash to break the chain
	corrupted := []byte(data)
	// Find "entry_hash" and change a character
	for i := 0; i < len(corrupted)-12; i++ {
		if string(corrupted[i:i+10]) == "entry_hash" {
			// Change a hex char after the hash value starts
			for j := i + 13; j < len(corrupted); j++ {
				if corrupted[j] >= 'a' && corrupted[j] <= 'f' {
					if corrupted[j] == 'a' {
						corrupted[j] = 'b'
					} else {
						corrupted[j] = 'a'
					}
					break
				}
			}
			break
		}
	}
	os.WriteFile(ledgerPath, corrupted, 0o600)

	// Verify should detect the break
	count, err := ledger.Verify(env.projectRoot)
	if err == nil {
		t.Error("expected verification error for corrupted ledger")
	}
	_ = count
}

// -------------------------------------------------------------------
// cmdExplain tests
// -------------------------------------------------------------------

func TestCmdExplain_EmptyLedger(t *testing.T) {
	env := newTestEnv(t)
	// Should not panic
	cmdExplain(env.projectRoot, -1)
}

func TestCmdExplain_LastEntry(t *testing.T) {
	env := newTestEnv(t)
	ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName:    "Read",
		Verb:        "read_ref",
		Target:      "src/main.go",
		Decision:    "allow",
		Reason:      "normal file read",
		Sensitivity: "",
		Trust:       "trusted",
		Provenance:  "user",
	})

	// Default (-1) = last entry
	cmdExplain(env.projectRoot, -1)
}

func TestCmdExplain_SpecificIndex(t *testing.T) {
	env := newTestEnv(t)
	for i := 0; i < 5; i++ {
		ledger.Append(env.projectRoot, &ledger.Entry{
			ToolName: "Bash",
			Verb:     "execute_dry_run",
			Target:   "ls",
			Decision: "allow",
			Reason:   "test",
		})
	}

	// Explain entry at index 2
	cmdExplain(env.projectRoot, 2)
}

func TestCmdExplain_FormatsEvidence(t *testing.T) {
	env := newTestEnv(t)
	if err := ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName:  "mcp__evil__record",
		Verb:      "mcp_credential_leak",
		Target:    "evil",
		Decision:  "deny",
		Reason:    "credential pattern in MCP args: customerData.AWS_ACCESS_KEY_ID contains AKIA",
		Evidence:  `{"customerData":{"AWS_ACCESS_KEY_ID":"[REDACTED:aws_access_key]"}}`,
		AlertType: "mcp_credential",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdExplain(env.projectRoot, -1)
	})
	if !strings.Contains(out, "Evidence (redacted):") {
		t.Fatalf("expected evidence section, got %s", out)
	}
	if !strings.Contains(out, "[REDACTED:aws_access_key]") {
		t.Fatalf("expected redacted evidence content, got %s", out)
	}
}

func TestCmdExplain_OmitsEvidenceWhenEmpty(t *testing.T) {
	env := newTestEnv(t)
	if err := ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName: "Read",
		Verb:     "read_ref",
		Target:   "README.md",
		Decision: "allow",
		Reason:   "normal file read",
	}); err != nil {
		t.Fatal(err)
	}

	out := captureStdout(t, func() {
		cmdExplain(env.projectRoot, -1)
	})
	if strings.Contains(out, "Evidence (redacted):") {
		t.Fatalf("did not expect evidence section, got %s", out)
	}
}

// -------------------------------------------------------------------
// cmdAllowHost tests (skipping interactive confirmation)
// -------------------------------------------------------------------

func TestCmdAllowHost_DuplicateDetection(t *testing.T) {
	env := newTestEnv(t)
	l := env.writeDefaultLease()

	// localhost is already in default approved_hosts
	for _, h := range l.ApprovedHosts {
		if h == "localhost" {
			// Calling cmdAllowHost should detect duplicate and return early
			cmdAllowHost(env.projectRoot, "localhost")

			// Verify lease unchanged (no duplication)
			reloaded, _ := lease.Load(env.leasePath)
			count := 0
			for _, rh := range reloaded.ApprovedHosts {
				if rh == "localhost" {
					count++
				}
			}
			if count != 1 {
				t.Errorf("expected exactly 1 'localhost', got %d", count)
			}
			return
		}
	}
	t.Skip("localhost not in default approved_hosts")
}

// -------------------------------------------------------------------
// cmdAllowRemote tests
// -------------------------------------------------------------------

func TestCmdAllowRemote_DuplicateDetection(t *testing.T) {
	env := newTestEnv(t)
	l := env.writeDefaultLease()

	// origin is already in default approved_remotes
	for _, r := range l.ApprovedRemotes {
		if r == "origin" {
			cmdAllowRemote(env.projectRoot, "origin")

			reloaded, _ := lease.Load(env.leasePath)
			count := 0
			for _, rr := range reloaded.ApprovedRemotes {
				if rr == "origin" {
					count++
				}
			}
			if count != 1 {
				t.Errorf("expected exactly 1 'origin', got %d", count)
			}
			return
		}
	}
	t.Skip("origin not in default approved_remotes")
}

// -------------------------------------------------------------------
// redactTargetIfSensitive tests
// -------------------------------------------------------------------

func TestRedactTargetIfSensitive(t *testing.T) {
	tests := []struct {
		verb     string
		target   string
		expected string
	}{
		// Non-read verbs are never redacted
		{"execute_dry_run", "/home/user/.env", "/home/user/.env"},
		{"stage_write", ".env", ".env"},

		// read_ref with sensitive paths
		{"read_ref", "/home/user/.env", ".env (path redacted)"},
		{"read_ref", "/home/user/.ssh/id_rsa", "id_rsa (path redacted)"},
		{"read_ref", "/app/credentials.json", "credentials.json (path redacted)"},
		// secrets.* is in sensitive_paths but "secrets" is not in redactTargetIfSensitive's list
		{"read_ref", "/project/secrets.yml", "/project/secrets.yml"},
		{"read_ref", "/home/user/.aws/config", "config (path redacted)"},
		{"read_ref", "/app/server.pem", "server.pem (path redacted)"},
		{"read_ref", "/app/private.key", "private.key (path redacted)"},
		{"read_ref", "/home/user/.netrc", ".netrc (path redacted)"},
		{"read_ref", "/home/user/.npmrc", ".npmrc (path redacted)"},

		// read_ref with non-sensitive paths
		{"read_ref", "src/main.go", "src/main.go"},
		{"read_ref", "README.md", "README.md"},
		{"read_ref", "package.json", "package.json"},
	}

	for _, tt := range tests {
		t.Run(tt.verb+"_"+filepath.Base(tt.target), func(t *testing.T) {
			got := redactTargetIfSensitive(tt.verb, tt.target)
			if got != tt.expected {
				t.Errorf("redactTargetIfSensitive(%q, %q) = %q, want %q",
					tt.verb, tt.target, got, tt.expected)
			}
		})
	}
}
