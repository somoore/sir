package main

import "testing"

// TestBacklogLabelSyncAnchors guards the explicit text anchors that the
// triage-backlog workflow parses from the rendered issue-form body.
func TestBacklogLabelSyncAnchors(t *testing.T) {
	root := repoRoot(t)

	requireContainsFile(t, root, ".github/ISSUE_TEMPLATE/backlog_entry.yml", "label: Track", "backlog form track anchor")
	requireContainsFile(t, root, ".github/ISSUE_TEMPLATE/backlog_entry.yml", "Mark as a good-first-security-change candidate", "backlog form good-first anchor")
	requireContainsFile(t, root, ".github/workflows/triage-backlog.yml", "### Track", "triage workflow track parser")
	requireContainsFile(t, root, ".github/workflows/triage-backlog.yml", "Mark as a good-first-security-change candidate", "triage workflow good-first parser")
}
