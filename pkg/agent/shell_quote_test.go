package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestShellQuotePath(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/Users/test/.local/bin/sir", "/Users/test/.local/bin/sir"},
		{"/Users/Jane Doe/.local/bin/sir", "'/Users/Jane Doe/.local/bin/sir'"},
		{"/tmp/a;curl evil/sir", "'/tmp/a;curl evil/sir'"},
		{"/tmp/$(id)/sir", "'/tmp/$(id)/sir'"},
		{"/tmp/it's/sir", `'/tmp/it'\''s/sir'`},
	}
	for _, tc := range cases {
		if got := ShellQuotePath(tc.in); got != tc.want {
			t.Errorf("ShellQuotePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestGenerateHooksConfigQuotesUnsafeBinaryPath(t *testing.T) {
	spec := &claudeSpec
	cfg, err := baseGenerateHooksConfigMap(spec, "/Users/Jane Doe/.local/bin/sir", "guard")
	if err != nil {
		t.Fatalf("baseGenerateHooksConfigMap: %v", err)
	}
	raw := cfg[spec.ConfigStrategy.ManagedSubtreeKey]
	if raw == nil {
		t.Fatalf("managed subtree %q missing", spec.ConfigStrategy.ManagedSubtreeKey)
	}
	encoded, ok := cfgString(raw)
	if !ok {
		t.Fatalf("could not stringify config: %#v", raw)
	}
	if !strings.Contains(encoded, "'/Users/Jane Doe/.local/bin/sir' guard ") {
		t.Fatalf("generated hook command did not quote the binary path:\n%s", encoded)
	}
}

func cfgString(v interface{}) (string, bool) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	return string(b), true
}
