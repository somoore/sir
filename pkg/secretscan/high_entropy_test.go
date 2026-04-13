package secretscan

import "testing"

// TestIsHighEntropyString_TruePositives verifies that real credential-shaped
// tokens are detected. These are alphanumeric with limited special chars,
// high entropy, and no URL/markup syntax.
func TestIsHighEntropyString_TruePositives(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		{"random_alphanumeric_48", "Zx8Qm1Nf7Vb4Lc2Kt9Pw5Hs3Jd6Rg8Ty0Ua1We2Ri3Po4Nk7"},
		{"random_mixed_case_40", "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV3wX4y"},
		{"go_build_id", "dQGKPHhB5tHxAMDHDRvFXNYW/sWMGCeCiTp1lU3t_bZ8u"},
		{"base64_token_no_padding", "eyJhbGciOiJIUzI1NiJ9eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !IsHighEntropyString(tc.token) {
				t.Errorf("expected true positive for %q (len=%d, entropy=%.2f)",
					tc.token, len(tc.token), shannonEntropy(tc.token))
			}
		})
	}
}

// TestIsHighEntropyString_FalsePositives verifies that non-credential strings
// are NOT flagged. These are URLs, markdown badges, env var examples, and
// other structured text that is long and varied but not a secret.
func TestIsHighEntropyString_FalsePositives(t *testing.T) {
	cases := []struct {
		name  string
		token string
	}{
		// Markdown badge URLs (the exact false positives from README.md)
		{
			"shields_badge_supports",
			"[![Supports](https://img.shields.io/badge/supports-Claude_%7C_Gemini_%7C_Codex-blueviolet)](#what-it-is)",
		},
		{
			"shields_badge_license",
			"Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)",
		},
		{
			"shields_badge_status",
			"[![Status:experimental](https://img.shields.io/badge/status-experimental-orange)](#hard-limits)",
		},
		// Env var examples from docs
		{
			"env_var_managed_policy",
			"SIR_MANAGED_POLICY_PATH=/etc/sir/managed-policy.json",
		},
		{
			"env_var_otlp_endpoint",
			"SIR_OTLP_ENDPOINT=https://collector.internal.example/v1/logs",
		},
		// URLs
		{
			"github_url",
			"https://github.com/somoore/sir/blob/main/scripts/verify-release.sh",
		},
		{
			"api_url",
			"https://api.github.com/repos/somoore/sir/releases?per_page=1",
		},
		// Cosign identity strings
		{
			"cosign_cert_identity",
			"https://github.com/somoore/sir/.github/workflows/release.yml@refs/tags/v0.0.2",
		},
		// Markdown links
		{
			"markdown_link",
			"[docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md)",
		},
		// HTML/markdown with brackets
		{
			"html_tag_with_attributes",
			"<div_align=\"center\">some-long-content-that-might-have-entropy</div>",
		},
		// Command line examples
		{
			"curl_command",
			"curl-fsSL-https://raw.githubusercontent.com/somoore/sir/main/scripts/download.sh",
		},
		// Query string URLs
		{
			"query_string_url",
			"https://securityscorecards.dev/viewer/?uri=github.com/somoore/sir",
		},
		// JSON-wrapped tool output (the actual root cause of the bug —
		// Claude Code returns tool results as JSON, and the opening
		// {"type":"text","file":{"filePath":"..." blob is one huge token
		// that triggers high-entropy detection)
		{
			"json_tool_output",
			`{"type":"text","file":{"filePath":"/Users/dev/project/README.md","content":"#`,
		},
		{
			"json_object",
			`{"version":"v0.0.2","installed_at":"2026-04-12T20:07:45Z","install_method":"source"}`,
		},
		{
			"absolute_file_path",
			"/Users/scottmoore/github/apfelbauer/findings/FM-03-supply-chain-delivery.md",
		},
		{
			"relative_file_path",
			"detection/splunk/apfelbauer-rules.spl",
		},
		// Short tokens (below 32 chars)
		{"short_token", "abc123def456ghi789"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if IsHighEntropyString(tc.token) {
				t.Errorf("false positive: %q should NOT be flagged (len=%d, entropy=%.2f)",
					tc.token, len(tc.token), shannonEntropy(tc.token))
			}
		})
	}
}

// TestScanOutputForCredentials_NoFalsePositiveOnREADME tests the exact README.md
// content that was triggering false positives and marking sessions as secret.
func TestScanOutputForCredentials_NoFalsePositiveOnREADME(t *testing.T) {
	// This is a representative chunk of the README.md that was triggering
	// high_entropy_token false positives via shields.io badge URLs.
	readmeChunk := `# sir — Sandbox in Reverse

[![Pre-alpha release](https://img.shields.io/github/v/release/somoore/sir?include_prereleases&label=pre-alpha&color=orange)](https://github.com/somoore/sir/releases/latest) [![Supports](https://img.shields.io/badge/supports-Claude_%7C_Gemini_%7C_Codex-blueviolet)](#what-it-is) [![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](#hard-limits)

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/somoore/sir/badge)](https://securityscorecards.dev/viewer/?uri=github.com/somoore/sir) [![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12462/badge)](https://www.bestpractices.dev/projects/12462) [![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Managed rollout** (enterprise): ` + "`export SIR_MANAGED_POLICY_PATH=/etc/sir/managed-policy.json && sir install --agent claude`" + `
`

	matches := ScanOutputForCredentials(readmeChunk)
	for _, m := range matches {
		if m.PatternName == "high_entropy_token" {
			t.Fatalf("README.md content triggered high_entropy_token false positive — this was the bug that blocked subagent delegation")
		}
	}
}

// TestScanOutputForCredentials_StillCatchesRealTokens verifies that the
// high_entropy filter does not suppress real credential detection.
// Real high-entropy tokens appear as standalone whitespace-delimited strings
// (e.g., in config dumps, log output, or JSON values), not embedded in
// key=value or URL syntax.
func TestScanOutputForCredentials_StillCatchesRealTokens(t *testing.T) {
	realToken := "Zx8Qm1Nf7Vb4Lc2Kt9Pw5Hs3Jd6Rg8Ty0Ua1We2Ri3Po4Nk7"
	output := "some normal text\n" + realToken + "\nmore text"
	matches := ScanOutputForCredentials(output)
	if !hasPattern(matches, "high_entropy_token") {
		t.Fatalf("real high-entropy token was not detected — patterns: %+v", matches)
	}
}

// TestScanOutputForCredentials_NamedPatternsWorkInJSON verifies that known
// credential formats (AWS keys, GitHub PATs, etc.) are detected even when
// embedded in JSON. Named patterns use regex on the full text, not
// whitespace splitting, so JSON wrapping doesn't affect them.
func TestScanOutputForCredentials_NamedPatternsWorkInJSON(t *testing.T) {
	output := `{"aws_key": "AKIAIOSFODNN7EXAMPLE1"}`
	matches := ScanOutputForCredentials(output)
	if !hasPattern(matches, "aws_access_key") {
		t.Fatalf("AWS key in JSON value was not detected — patterns: %+v", matches)
	}
}

func TestScanOutputForCredentials_NoFalsePositiveOnFilePathHeavyOutput(t *testing.T) {
	output := `=== Checking platform line updated ===
/Users/scottmoore/github/apfelbauer/findings/FM-03-supply-chain-delivery.md:1
/Users/scottmoore/github/apfelbauer/findings/FM-04-full-attack-chain.md:1
`
	matches := ScanOutputForCredentials(output)
	for _, m := range matches {
		if m.PatternName == "high_entropy_token" {
			t.Fatalf("file path output triggered high_entropy_token false positive — this should not taint the session")
		}
	}
}
