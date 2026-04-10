package hooks

import (
	"testing"
	"time"

	"github.com/somoore/sir/pkg/ledger"
)

// TestComputeSessionStats_ScopedToSessionStart reproduces the bug summarized
// in docs/research/validation-summary.md: session-summary counts leaked across sessions
// because the old implementation summed every entry in the ledger. The fix is
// a `since` floor sourced from session.State.StartedAt. This test locks in
// the filter so the bug cannot regress.
func TestComputeSessionStats_ScopedToSessionStart(t *testing.T) {
	base := time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		// Previous session — should be excluded.
		{Timestamp: base.Add(-10 * time.Minute), Decision: "deny"},
		{Timestamp: base.Add(-9 * time.Minute), Decision: "ask"},
		{Timestamp: base.Add(-8 * time.Minute), Decision: "allow"},
		// Current session — should all be counted.
		{Timestamp: base.Add(1 * time.Second), Decision: "allow"},
		{Timestamp: base.Add(2 * time.Second), Decision: "allow"},
		{Timestamp: base.Add(3 * time.Second), Decision: "ask"},
		{Timestamp: base.Add(4 * time.Second), Decision: "alert"},
	}

	got := computeSessionStats(entries, base)

	if got.TotalEntries != 4 {
		t.Errorf("TotalEntries = %d, want 4 (pre-session entries should be filtered)", got.TotalEntries)
	}
	if got.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", got.Allowed)
	}
	if got.Asked != 1 {
		t.Errorf("Asked = %d, want 1", got.Asked)
	}
	if got.Blocked != 0 {
		t.Errorf("Blocked = %d, want 0 — the 1 stale deny from the previous session must not leak into this session's summary", got.Blocked)
	}
	if got.Alerts != 1 {
		t.Errorf("Alerts = %d, want 1", got.Alerts)
	}
}

// TestComputeSessionStats_ZeroSinceCountsEverything verifies the fallback
// path when session state is unreadable: zero `since` means "no floor" so
// every entry is counted. Preserves the legacy behaviour for fresh projects
// that have a ledger but no session.json yet.
func TestComputeSessionStats_ZeroSinceCountsEverything(t *testing.T) {
	entries := []ledger.Entry{
		{Timestamp: time.Unix(1000, 0), Decision: "allow"},
		{Timestamp: time.Unix(2000, 0), Decision: "deny"},
		{Timestamp: time.Unix(3000, 0), Decision: "ask"},
		{Timestamp: time.Unix(4000, 0), Decision: "alert"},
	}
	got := computeSessionStats(entries, time.Time{})
	if got.TotalEntries != 4 || got.Allowed != 1 || got.Blocked != 1 || got.Asked != 1 || got.Alerts != 1 {
		t.Errorf("with zero since, expected all 4 entries counted once each, got %+v", got)
	}
}

// TestComputeSessionStats_BoundaryInclusive verifies that an entry with
// timestamp equal to `since` is included — "at or after the session start".
func TestComputeSessionStats_BoundaryInclusive(t *testing.T) {
	start := time.Date(2026, 4, 8, 14, 0, 0, 0, time.UTC)
	entries := []ledger.Entry{
		{Timestamp: start.Add(-time.Nanosecond), Decision: "deny"},
		{Timestamp: start, Decision: "allow"},
	}
	got := computeSessionStats(entries, start)
	if got.TotalEntries != 1 || got.Allowed != 1 || got.Blocked != 0 {
		t.Errorf("boundary at `since` should be included; got %+v", got)
	}
}
