package main

import "testing"

func TestRequireHumanConfirmationInvokesGate(t *testing.T) {
	orig := humanConfirmation
	t.Cleanup(func() { humanConfirmation = orig })

	var got string
	humanConfirmation = func(action string) error {
		got = action
		return nil
	}
	requireHumanConfirmation("approve")
	if got != "approve" {
		t.Fatalf("confirmation received %q, want %q", got, "approve")
	}
}

func TestMutatingCommandPredicates(t *testing.T) {
	readOnlyPolicy := [][]string{{}, {"show"}, {"diff", "--strict"}, {"suggest"}}
	for _, args := range readOnlyPolicy {
		if !policyCommandIsReadOnly(args) {
			t.Errorf("policyCommandIsReadOnly(%v) = false, want true", args)
		}
	}
	for _, args := range [][]string{{"init", "--personal", "--yes"}, {"protect-path", ".env"}, {"unprotect-path", ".env"}} {
		if policyCommandIsReadOnly(args) {
			t.Errorf("policyCommandIsReadOnly(%v) = true, want false", args)
		}
	}

	for _, args := range [][]string{{}, {"status"}, {"inventory"}, {"list"}, {"--agent", "claude"}, {"scope"}, {"scope", "list"}, {"scope", "--project", "/tmp/x", "list"}, {"scope", "--project=/tmp/x"}} {
		if !mcpCommandIsReadOnly(args) {
			t.Errorf("mcpCommandIsReadOnly(%v) = false, want true", args)
		}
	}
	for _, args := range [][]string{{"approve", "x"}, {"revoke", "x"}, {"scope", "x", "--allow-network"}, {"scope", "revoke", "x"}, {"scope", "--project", "/tmp/x", "x"}, {"wrap", "--yes"}} {
		if mcpCommandIsReadOnly(args) {
			t.Errorf("mcpCommandIsReadOnly(%v) = true, want false", args)
		}
	}

	if logCommandIsReadOnly([]string{"archive", "--prune", "--yes"}) {
		t.Error("log archive must not be read-only")
	}
	if !logCommandIsReadOnly([]string{"verify"}) {
		t.Error("log verify must be read-only")
	}
}
