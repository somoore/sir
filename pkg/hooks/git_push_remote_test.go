// git_push_remote_test.go — regression guards for the `git push`
// remote-name extraction bug observed in live usage: a command like
// `git push 2>&1 | tail -5` produced the fix suggestion
// `sir allow-remote git push 2>&1 | tail -5` because the raw command
// string was leaking into the FormatBlockPush formatter as the remote
// name. The shell classifier now extracts the remote explicitly and
// populates Intent.RemoteName, the message formatter uses that field,
// and extractGitRemote skips shell-redirect tokens.
package hooks

import (
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// TestExtractGitRemote_StripsShellRedirects verifies that tokens like
// `2>&1`, `>`, `<`, `&>`, `|`, `;`, `&&`, `||` are not interpreted as
// remote names. strings.Fields will happily split `git push 2>&1`
// into `["git", "push", "2>&1"]`, so without the shell-meta filter
// extractGitRemote would pick `2>&1` as the remote.
func TestExtractGitRemote_StripsShellRedirects(t *testing.T) {
	cases := []struct {
		name string
		cmd  string
		want string
	}{
		{"bare push", "git push", ""},
		{"push origin", "git push origin", "origin"},
		{"push origin main", "git push origin main", "origin"},
		{"push -u origin main", "git push -u origin main", "origin"},
		{"push --force origin", "git push --force origin", "origin"},
		{"redirect stderr", "git push 2>&1", ""},
		{"redirect stdout", "git push > /tmp/out", ""},
		{"redirect append", "git push >> /tmp/log", ""},
		{"combined redirect", "git push &> /dev/null", ""},
		{"pipeline remnant", "git push | tee log", ""},
		{"origin then redirect", "git push origin 2>&1", "origin"},
		{"upstream flag then redirect", "git push -u origin 2>&1", "origin"},
		{"logical and remnant", "git push && echo done", ""},
		{"semicolon remnant", "git push ; echo done", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractGitRemote(tc.cmd)
			if got != tc.want {
				t.Errorf("ExtractGitRemote(%q) = %q, want %q", tc.cmd, got, tc.want)
			}
		})
	}
}

// TestMapShellCommand_GitPushPopulatesRemoteName verifies that the shell
// classifier populates Intent.RemoteName when classifying a git push,
// even when the command contains shell syntax that the raw Target
// string would otherwise contain. Substitutes "origin" when no explicit
// remote is given (matching git's default).
func TestMapShellCommand_GitPushPopulatesRemoteName(t *testing.T) {
	l := lease.DefaultLease()
	cases := []struct {
		name       string
		cmd        string
		wantVerb   string
		wantRemote string
	}{
		{
			name:       "bare push defaults to origin",
			cmd:        "git push",
			wantVerb:   "push_origin",
			wantRemote: "origin",
		},
		{
			name:       "push with stderr redirect still yields origin",
			cmd:        "git push 2>&1",
			wantVerb:   "push_origin",
			wantRemote: "origin",
		},
		{
			name:       "push to unapproved remote",
			cmd:        "git push evil-fork main",
			wantVerb:   "push_remote",
			wantRemote: "evil-fork",
		},
		{
			name:       "push to unapproved remote with stderr redirect",
			cmd:        "git push evil-fork 2>&1",
			wantVerb:   "push_remote",
			wantRemote: "evil-fork",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mapShellCommand(tc.cmd, l)
			if string(got.Verb) != tc.wantVerb {
				t.Errorf("verb = %q, want %q", got.Verb, tc.wantVerb)
			}
			if got.RemoteName != tc.wantRemote {
				t.Errorf("RemoteName = %q, want %q", got.RemoteName, tc.wantRemote)
			}
		})
	}
}

// TestMapShellCommand_GitPushCompoundPropagatesRemoteName is the load-
// bearing regression case for the live bug: `git push 2>&1 | tail -5`
// splits on `|` into `["git push 2>&1", "tail -5"]`; the git-push
// segment must contribute RemoteName to the compound intent so the
// deny-message formatter has a clean value to use instead of the raw
// `trimmed` command string.
func TestMapShellCommand_GitPushCompoundPropagatesRemoteName(t *testing.T) {
	l := lease.DefaultLease()
	got := mapShellCommand("git push 2>&1 | tail -5", l)
	if string(got.Verb) != "push_origin" {
		t.Errorf("verb = %q, want push_origin (git's default remote is approved)", got.Verb)
	}
	if got.RemoteName != "origin" {
		t.Errorf("RemoteName = %q, want %q (compound propagation lost)", got.RemoteName, "origin")
	}
	// And the Target still shows the full compound for the ledger —
	// that is the existing contract we must not break.
	if !strings.Contains(got.Target, "git push 2>&1 | tail -5") {
		t.Errorf("Target = %q, expected full compound command for ledger display", got.Target)
	}
}

// TestMapShellCommand_GitPushUnapprovedCompoundPropagatesRemoteName is
// the full live-bug reproduction: an unapproved remote in a compound
// that contains shell redirects and a pipe. The resulting Intent must
// carry the correct verb AND a remote name the formatter can use to
// build `sir allow-remote evil-fork`.
func TestMapShellCommand_GitPushUnapprovedCompoundPropagatesRemoteName(t *testing.T) {
	l := lease.DefaultLease()
	got := mapShellCommand("git push evil-fork main 2>&1 | tail -5", l)
	if got.Verb != "push_remote" {
		t.Errorf("verb = %q, want push_remote", got.Verb)
	}
	if got.RemoteName != "evil-fork" {
		t.Errorf("RemoteName = %q, want evil-fork (extracted from compound)", got.RemoteName)
	}
}
