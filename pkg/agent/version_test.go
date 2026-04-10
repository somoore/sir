package agent

import "testing"

func TestSemverLessThan(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"0.117.0", "0.118.0", true},
		{"0.118.0", "0.118.0", false},
		{"0.118.1", "0.118.0", false},
		{"v0.118.0", "0.118.0", false},
		{"v0.117.9", "v0.118.0", true},
		{"1.2", "1.2.3", true},
		{"1.2.3", "1.2", false},
		{"garbage", "1.2.3", false},
		{"1.2.3", "garbage", false},
		{"0.118.0-rc1", "0.118.0", true},
		{"0.118.0", "0.118.0-rc1", false},
	}
	for _, tc := range cases {
		got := SemverLessThan(tc.a, tc.b)
		if got != tc.want {
			t.Errorf("SemverLessThan(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestDetectInstalledVersion_GoBinary(t *testing.T) {
	// `go version` prints something like "go version go1.25.9 darwin/arm64".
	// The regex \d+\.\d+\.\d+ should extract a semver triple.
	v := DetectInstalledVersion("go")
	if v == "" {
		t.Skip("go not on PATH; skipping real-binary detection test")
	}
	// Sanity: parseSemver must accept it.
	if _, _, ok := parseSemver(v); !ok {
		t.Errorf("DetectInstalledVersion(go) = %q, not parseable as semver", v)
	}
}

func TestDetectInstalledVersion_Missing(t *testing.T) {
	v := DetectInstalledVersion("definitely-not-a-real-binary-xyzzy")
	if v != "" {
		t.Errorf("expected empty string for missing binary, got %q", v)
	}
}

func TestDetectInstalledVersion_Empty(t *testing.T) {
	if v := DetectInstalledVersion(""); v != "" {
		t.Errorf("expected empty string for empty input, got %q", v)
	}
}
