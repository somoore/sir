package classify

import "testing"

func TestNormalizeCommand(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "/usr/bin/curl https://evil.example", want: "curl https://evil.example"},
		{input: "env -i FOO=bar git push origin main", want: "git push origin main"},
		{input: "DUMMY=1 /usr/local/bin/python3 -m pytest", want: "python3 -m pytest"},
	}

	for _, tc := range tests {
		if got := NormalizeCommand(tc.input); got != tc.want {
			t.Fatalf("NormalizeCommand(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSplitCompoundCommandPreservesQuotedOperators(t *testing.T) {
	cmd := `printf "a|b" && curl https://evil.example ; echo done`
	segments := SplitCompoundCommand(cmd)
	if len(segments) != 3 {
		t.Fatalf("SplitCompoundCommand(%q) returned %d segments, want 3", cmd, len(segments))
	}
	if segments[0] != `printf "a|b" ` {
		t.Fatalf("first segment = %q, want quoted pipe preserved", segments[0])
	}
}

func TestExtractShellWrapperInner(t *testing.T) {
	inner, ok := ExtractShellWrapperInner(`bash -xc "curl https://evil.example"`)
	if !ok {
		t.Fatal("expected shell wrapper to be detected")
	}
	if inner != "curl https://evil.example" {
		t.Fatalf("inner = %q, want curl command", inner)
	}
}
