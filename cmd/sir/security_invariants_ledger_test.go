package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func runInvariantCrossVersionLineageStateCompatibility(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)
	stateDir := session.StateDir(env.projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("mkdir state dir: %v", err)
	}

	derivedPath := filepath.Join(env.projectRoot, "report.txt")
	legacySession := map[string]interface{}{
		"session_id":   "legacy-lineage-session",
		"project_root": env.projectRoot,
		"started_at":   "2026-01-01T00:00:00Z",
		"turn_counter": 4,
		"active_evidence": []map[string]interface{}{{
			"id":          "e1",
			"source_kind": fixture.Expected["source_kind"],
			"source_ref":  "mcp__slack__post_message",
			"turn":        4,
			"confidence":  "high",
			"labels": []map[string]string{{
				"sensitivity": fixture.Expected["label_sensitivity"],
				"trust":       "trusted",
				"provenance":  "mcp_tool",
			}},
			"recorded_at": "2026-01-01T00:00:00Z",
		}},
		"derived_file_lineage": map[string]interface{}{
			derivedPath: map[string]interface{}{
				"evidence_ids": []string{"e1"},
				"labels": []map[string]string{{
					"sensitivity": fixture.Expected["label_sensitivity"],
					"trust":       "trusted",
					"provenance":  "mcp_tool",
				}},
				"updated_at": "2026-01-01T00:00:01Z",
			},
		},
	}
	data, err := json.MarshalIndent(legacySession, "", "  ")
	if err != nil {
		t.Fatalf("marshal legacy lineage session: %v", err)
	}
	if err := os.WriteFile(session.StatePath(env.projectRoot), data, 0o600); err != nil {
		t.Fatalf("write legacy lineage session: %v", err)
	}

	loaded, err := session.Load(env.projectRoot)
	if err != nil {
		t.Fatalf("session.Load lineage payload: %v", err)
	}
	if got, want := len(loaded.ActiveEvidence), 1; got != want {
		t.Fatalf("ActiveEvidence len = %d, want %d", got, want)
	}
	if loaded.ActiveEvidence[0].SourceKind != fixture.Expected["source_kind"] {
		t.Fatalf("ActiveEvidence[0].SourceKind = %q, want %q", loaded.ActiveEvidence[0].SourceKind, fixture.Expected["source_kind"])
	}
	labels := loaded.DerivedLabelsForPath(derivedPath)
	if len(labels) != 1 {
		t.Fatalf("DerivedLabelsForPath len = %d, want 1", len(labels))
	}
	if labels[0].Sensitivity != fixture.Expected["label_sensitivity"] {
		t.Fatalf("DerivedLabelsForPath sensitivity = %q, want %q", labels[0].Sensitivity, fixture.Expected["label_sensitivity"])
	}
}

func runInvariantCrossVersionLedgerCompatibility(t *testing.T, fixture securityInvariantFixture) {
	t.Helper()
	env := newTestEnv(t)

	legacyEntry := map[string]interface{}{
		"index":        0,
		"timestamp":    "2026-01-01T00:00:00Z",
		"prev_hash":    strings.Repeat("0", 64),
		"tool_name":    "mcp__slack__post_message",
		"verb":         "mcp_unapproved",
		"target":       "slack",
		"decision":     "deny",
		"reason":       "legacy ledger compatibility fixture",
		"alert_type":   fixture.Expected["alert_type"],
		"evidence":     "{\"warning\":\"legacy evidence\"}",
		"diff_summary": "legacy diff summary",
		"entry_hash":   "",
	}
	legacyEntry["entry_hash"] = computeLegacyInvariantLedgerHash(legacyEntry)
	line, err := json.Marshal(legacyEntry)
	if err != nil {
		t.Fatalf("marshal legacy ledger fixture: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(ledger.LedgerPath(env.projectRoot)), 0o700); err != nil {
		t.Fatalf("mkdir legacy ledger dir: %v", err)
	}
	if err := os.WriteFile(ledger.LedgerPath(env.projectRoot), append(line, '\n'), 0o600); err != nil {
		t.Fatalf("write legacy ledger fixture: %v", err)
	}

	entries, err := ledger.ReadAll(env.projectRoot)
	if err != nil {
		t.Fatalf("ledger.ReadAll legacy fixture: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("ledger.ReadAll len = %d, want 1", len(entries))
	}
	if entries[0].AlertType != fixture.Expected["alert_type"] {
		t.Fatalf("legacy alert_type = %q, want %q", entries[0].AlertType, fixture.Expected["alert_type"])
	}

	if err := ledger.Append(env.projectRoot, &ledger.Entry{
		ToolName: "Bash",
		Verb:     "execute_dry_run",
		Target:   "git status",
		Decision: "allow",
		Reason:   "append after legacy ledger fixture",
	}); err != nil {
		t.Fatalf("ledger.Append after legacy fixture: %v", err)
	}

	count, err := ledger.Verify(env.projectRoot)
	if err != nil {
		t.Fatalf("ledger.Verify mixed payload: %v", err)
	}
	if got, want := count, 2; got != want {
		t.Fatalf("ledger.Verify count = %d, want %d", got, want)
	}
}
