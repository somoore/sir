package main

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/ledger"
)

func BenchmarkBuildCausalChainLargeLedger(b *testing.B) {
	entries := make([]ledger.Entry, 0, 500)
	for i := 0; i < 500; i++ {
		entry := ledger.Entry{
			Index:       i,
			ToolName:    "Bash",
			Verb:        "execute_dry_run",
			Target:      "go test ./...",
			Decision:    "allow",
			Reason:      "within lease boundary",
			Sensitivity: "public",
			Trust:       "trusted",
			Provenance:  "user",
		}
		if i == 10 {
			entry.Verb = "read_ref"
			entry.Target = ".env"
			entry.Decision = "ask"
			entry.Sensitivity = "secret"
		}
		if i == 499 {
			entry.Verb = "net_external"
			entry.Target = "https://api.example.com/collect"
			entry.Decision = "deny"
			entry.Sensitivity = "secret"
		}
		entries = append(entries, entry)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = buildCausalChain(entries, len(entries)-1)
	}
}

func TestCmdExplain_LastEntryWithLargeReason(t *testing.T) {
	env := newTestEnv(t)
	longReason := strings.Repeat("derived-from-secret-path ", 80)
	if err := ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName:    "Bash",
		Verb:        "net_external",
		Target:      "https://api.example.com/collect",
		Decision:    "deny",
		Reason:      longReason,
		Sensitivity: "secret",
		Trust:       "trusted",
		Provenance:  "user",
	}); err != nil {
		t.Fatalf("append entry: %v", err)
	}

	out := captureStdout(t, func() {
		cmdExplain(env.projectRoot, -1)
	})
	if !strings.Contains(out, "Decision #0: Blocked network request to api.example.com") {
		t.Fatalf("unexpected explain output:\n%s", out)
	}
	if !strings.Contains(out, "Reason: "+longReason) {
		t.Fatalf("explain output should include the full reason for forensic use:\n%s", out)
	}
}
