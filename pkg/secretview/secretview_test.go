package secretview

import "testing"

func TestRedact_EnvFileKeysOnly(t *testing.T) {
	content := []byte(`# database config
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DEBUG=true
EMPTY=
`)
	v := Redact(".env", content)
	if v.Kind != "env" {
		t.Fatalf("kind = %q, want env", v.Kind)
	}
	if v.CommentLines != 1 {
		t.Errorf("comment lines = %d, want 1", v.CommentLines)
	}
	byKey := map[string]Entry{}
	for _, e := range v.Entries {
		byKey[e.Key] = e
	}
	if len(byKey) != 4 {
		t.Fatalf("got %d keys, want 4: %+v", len(byKey), v.Entries)
	}
	if e := byKey["AWS_ACCESS_KEY_ID"]; !e.Present || e.ValueLen != len("AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AWS_ACCESS_KEY_ID entry wrong: %+v", e)
	}
	if e := byKey["EMPTY"]; e.Present || e.ValueLen != 0 {
		t.Errorf("EMPTY should be empty: %+v", e)
	}
	if byKey["AWS_ACCESS_KEY_ID"].Class == "" {
		t.Errorf("expected AWS key to be classified as credential-like")
	}
	if v.CredentialHits < 1 {
		t.Errorf("expected at least 1 credential hit, got %d", v.CredentialHits)
	}
}

func TestRedact_NeverEmitsValues(t *testing.T) {
	secret := "AKIAIOSFODNN7EXAMPLE"
	v := Redact(".env", []byte("KEY="+secret))
	// No field on the View or its entries should carry the raw value.
	for _, e := range v.Entries {
		if e.Class == secret || e.Key == secret {
			t.Fatalf("raw value leaked into view: %+v", e)
		}
	}
}

func TestRedact_OpaqueFile(t *testing.T) {
	content := []byte("-----BEGIN PRIVATE KEY-----\nMIIBVwIBADAN...\n-----END PRIVATE KEY-----\n")
	v := Redact("id_rsa", content)
	if v.Kind != "opaque" {
		t.Errorf("kind = %q, want opaque", v.Kind)
	}
	if v.Bytes != len(content) {
		t.Errorf("bytes = %d, want %d", v.Bytes, len(content))
	}
}

func TestSplitEnvLine(t *testing.T) {
	cases := []struct {
		line             string
		wantKey, wantVal string
		ok               bool
	}{
		{"FOO=bar", "FOO", "bar", true},
		{"export FOO=bar", "FOO", "bar", true},
		{`FOO="quoted value"`, "FOO", "quoted value", true},
		{"FOO='single'", "FOO", "single", true},
		{"not an assignment", "", "", false},
		{"=novalue", "", "", false},
		{"BAD KEY=x", "", "", false}, // space in key
	}
	for _, c := range cases {
		k, val, ok := splitEnvLine(c.line)
		if ok != c.ok || k != c.wantKey || val != c.wantVal {
			t.Errorf("splitEnvLine(%q) = (%q,%q,%v), want (%q,%q,%v)", c.line, k, val, ok, c.wantKey, c.wantVal, c.ok)
		}
	}
}

func TestLooksLikeEnv_ByContent(t *testing.T) {
	lines := []string{"A=1", "B=2", "# comment", "C=3"}
	if !looksLikeEnv("config.txt", lines) {
		t.Error("majority-assignment content should be treated as env")
	}
	prose := []string{"hello world", "this is prose", "A=1"}
	if looksLikeEnv("notes.txt", prose) {
		t.Error("mostly-prose content should not be treated as env")
	}
}
