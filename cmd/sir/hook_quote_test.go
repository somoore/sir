package main

import "testing"

func TestIsSirHookCommand_RecognizesQuotedPath(t *testing.T) {
	cases := []string{
		"'/Users/Jane Doe/.local/bin/sir' guard evaluate --agent claude",
		"/opt/homebrew/bin/sir guard post-evaluate",
		"sir guard evaluate",
	}
	for _, cmd := range cases {
		if !isSirHookCommand(cmd) {
			t.Errorf("isSirHookCommand(%q) = false, want true", cmd)
		}
	}
	if isSirHookCommand("'/usr/bin/not-sir' guard evaluate") {
		t.Error("non-sir binary must not match")
	}
}
