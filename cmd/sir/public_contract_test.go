package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
)

// TestPublicContractParity treats selected contributor-facing guarantees as an
// executable spec. The checked docs are an explicit allowlist so failures stay
// actionable and sprawl does not quietly return.
func TestPublicContractParity(t *testing.T) {
	root := repoRoot(t)
	ciWorkflowPath := filepath.Join(root, ".github", "workflows", "ci.yml")
	releaseWorkflowPath := filepath.Join(root, ".github", "workflows", "release.yml")

	rustVersion := mustFindLineValue(t, readFile(t, root, "rust-toolchain.toml"), `channel = "`, `"`)
	goMod := readFile(t, root, "go.mod")
	goMin := mustFindWordAfterPrefix(t, goMod, "go ")
	goToolchain := mustFindWordAfterPrefix(t, goMod, "toolchain go")
	securityEmail := mustFindLineValue(t, readFile(t, root, "SECURITY.md"), "- **Email:** ", "")

	t.Run("toolchain_versions", func(t *testing.T) {
		if _, err := os.Stat(ciWorkflowPath); err != nil {
			if os.IsNotExist(err) {
				t.Skip("CI workflow absent in this repo state")
			}
			t.Fatalf("stat %s: %v", ciWorkflowPath, err)
		}
		if _, err := os.Stat(releaseWorkflowPath); err != nil {
			if os.IsNotExist(err) {
				t.Skip("release workflow absent in this repo state")
			}
			t.Fatalf("stat %s: %v", releaseWorkflowPath, err)
		}
		requireContainsFile(t, root, "Makefile", fmt.Sprintf("RUST_VERSION ?= %s", rustVersion), "Makefile Rust version")
		requireContainsFile(t, root, "Makefile", fmt.Sprintf("GO_VERSION   ?= %s", goToolchain), "Makefile Go toolchain")
		requireContainsFile(t, root, "install.sh", fmt.Sprintf("RUST_VERSION=\"%s\"", rustVersion), "install.sh Rust version")
		requireContainsFile(t, root, "install.sh", fmt.Sprintf("GO_MIN_VERSION=\"%s\"", goMin), "install.sh Go minimum")
		requireContainsFile(t, root, ".github/workflows/ci.yml", fmt.Sprintf("RUST_VERSION: \"%s\"", rustVersion), "CI Rust pin")
		requireContainsFile(t, root, ".github/workflows/ci.yml", fmt.Sprintf("GO_VERSION: \"%s\"", goToolchain), "CI Go pin")
		requireContainsFile(t, root, ".github/workflows/release.yml", fmt.Sprintf("RUST_VERSION: \"%s\"", rustVersion), "release Rust pin")
		requireContainsFile(t, root, ".github/workflows/release.yml", fmt.Sprintf("GO_VERSION: \"%s\"", goToolchain), "release Go pin")
		requireContainsFile(t, root, "CONTRIBUTING.md", fmt.Sprintf("- **Rust** (%s+): [rustup.rs](https://rustup.rs/)", rustVersion), "CONTRIBUTING Rust prerequisite")
		requireContainsFile(t, root, "CONTRIBUTING.md", fmt.Sprintf("- **Go** (%s+): [go.dev/dl](https://go.dev/dl/)", goMin), "CONTRIBUTING Go prerequisite")
		requireContainsFile(t, root, "README.md", fmt.Sprintf("# Requires [Rust %s+](https://rustup.rs/)", rustVersion), "README Rust prerequisite")
		requireContainsFile(t, root, "README.md", fmt.Sprintf("# Requires [Go %s+](https://go.dev/dl/) with toolchain auto-fetch to go%s", goMin, goToolchain), "README Go prerequisite")
		requireContainsFile(t, root, "docs/contributor/supply-chain-policy.md", fmt.Sprintf("| Rust | %s |", rustVersion), "supply-chain Rust row")
		requireContainsFile(t, root, "docs/contributor/supply-chain-policy.md", fmt.Sprintf("| Go | %s minimum / %s toolchain |", goMin, goToolchain), "supply-chain Go row")
	})

	t.Run("security_contact_and_governance", func(t *testing.T) {
		requireContainsFile(t, root, "CONTRIBUTING.md", fmt.Sprintf("- **Email:** %s", securityEmail), "CONTRIBUTING security contact")
		requireContainsFile(t, root, "CONTRIBUTING.md", "[Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md)", "CONTRIBUTING code-of-conduct link")
		requireFileExists(t, root, "CODE_OF_CONDUCT.md")
		requireFileExists(t, root, "CHANGELOG.md")
	})

	t.Run("supported_release_line", func(t *testing.T) {
		requireContainsFile(t, root, "SECURITY.md", fmt.Sprintf("| %s (current) | Yes |", releaseSeries(Version)), "SECURITY supported release line")
	})

	t.Run("readme_contract", func(t *testing.T) {
		body := readFile(t, root, "README.md")
		requireOrderedSubstrings(t, body,
			"## What it is",
			"## Why use sir",
			"## Install in 3 minutes",
			"## Prove it works",
			"## Hard limits",
		)
		requireContainsFile(t, root, "README.md", "sir status", "README verification status command")
		requireContainsFile(t, root, "README.md", "sir doctor", "README verification doctor command")
		requireContainsFile(t, root, "README.md", "sir log verify", "README verification log verify command")
		requireContainsFile(t, root, "README.md", "sir install            # auto-detect supported agents already on this machine", "README auto-detect install guidance")
		requireContainsFile(t, root, "README.md", "Ask the agent to read `.env`", "README secret-read check")
		requireContainsFile(t, root, "README.md", "curl https://httpbin.org/get", "README blocked egress check")
	})

	t.Run("cli_support_surface", func(t *testing.T) {
		requireContainsFile(t, root, "cmd/sir/main.go", "case \"support\":", "main support dispatch")
		requireContainsFile(t, root, "cmd/sir/main.go", "sir support --json", "main support usage")
	})

	t.Run("agent_support_policy", func(t *testing.T) {
		requireGeneratedBlock(t, root, "README.md", "GENERATED SUPPORT SUMMARY", agent.RenderReadmeSupportBlock())
		requireGeneratedBlock(t, root, "docs/user/faq.md", "GENERATED SUPPORT FAQ", agent.RenderFAQSupportBlock())
		requireGeneratedBlock(t, root, "docs/research/sir-threat-model.md", "GENERATED SUPPORT SCOPE", agent.RenderThreatModelScopeBlock())
		requireGeneratedBlock(t, root, "docs/user/claude-code-hooks-integration.md", "GENERATED CLAUDE SUPPORT MATRIX", agent.RenderClaudeSupportMatrixBlock())
		requireGeneratedBlock(t, root, "docs/user/gemini-support.md", "GENERATED SUPPORT DOC", agent.RenderSupportDocBlock(agent.Gemini))
		requireGeneratedBlock(t, root, "docs/user/codex-support.md", "GENERATED SUPPORT DOC", agent.RenderSupportDocBlock(agent.Codex))
		requireContainsFile(t, root, "docs/user/claude-code-hooks-integration.md", "**Gemini CLI 0.36.0+ with near-parity support**", "Claude hooks integration Gemini tier")
		requireContainsFile(t, root, "docs/user/claude-code-hooks-integration.md", "**Codex 0.118.0+ has limited support**", "Claude hooks integration Codex tier")
		requireContainsFile(t, root, "docs/user/codex-support.md", "sir writes `~/.codex/hooks.json` and may create or update `~/.codex/config.toml`", "Codex support config.toml guidance")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "Codex remains limited support with a **Bash-only** hook surface", "verification guide Codex tier")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "auto-detected or explicitly selected agent configs gain sir hook entries", "verification guide auto-detect install guidance")
	})

	t.Run("runtime_and_managed_contract", func(t *testing.T) {
		requireContainsFile(t, root, "README.md", "SIR_MANAGED_POLICY_PATH", "README managed mode activation")
		requireContainsFile(t, root, "README.md", "`sir run <agent>`", "README runtime containment mention")
		requireContainsFile(t, root, "README.md", "measured preview", "README measured-preview runtime note")
		requireContainsFile(t, root, "docs/user/runtime-security-overview.md", "measured preview", "runtime overview measured-preview note")
		requireContainsFile(t, root, "docs/research/validation-summary.md", "measured preview", "validation summary measured-preview note")
		requireContainsFile(t, root, "docs/user/runtime-security-overview.md", "blocked/allowed egress counts", "runtime overview receipt visibility")
		requireContainsFile(t, root, "docs/research/validation-summary.md", "blocked/allowed egress counts", "validation summary receipt visibility")
		requireContainsFile(t, root, "docs/research/sir-threat-model.md", "Managed mode shifts the trust anchor", "threat model managed mode")
		requireContainsFile(t, root, "docs/research/sir-threat-model.md", "launch-time DNS pinning", "threat model runtime containment")
	})

	t.Run("contributor_workflow_contract", func(t *testing.T) {
		requireContainsFile(t, root, "Makefile", "contributor-check:", "Makefile contributor-check target")
		requireContainsFile(t, root, "Makefile", "bench:", "Makefile bench target")
		requireContainsFile(t, root, "Makefile", "bench-check:", "Makefile bench-check target")
		requireContainsFile(t, root, "Makefile", "verify-release:", "Makefile verify-release target")
		requireFileExists(t, root, ".github/workflows/actionlint.yml")
		requireFileExists(t, root, ".github/workflows/post-merge.yml")
		requireFileExists(t, root, ".github/workflows/triage-backlog.yml")
		requireFileExists(t, root, ".github/ISSUE_TEMPLATE/backlog_entry.yml")
		requireFileExists(t, root, ".github/ISSUE_TEMPLATE/config.yml")
		requireFileExists(t, root, "scripts/check_review_context.sh")
		requireFileExists(t, root, "scripts/verify-release.sh")
		requireFileExists(t, root, "docs/contributor/core-mental-model.md")
		requireFileExists(t, root, "docs/contributor/security-engineering-core.md")
		requireContainsFile(t, root, "CONTRIBUTING.md", "make contributor-check", "CONTRIBUTING contributor-check guidance")
		requireContainsFile(t, root, "CONTRIBUTING.md", "make bench", "CONTRIBUTING bench guidance")
		requireContainsFile(t, root, "CONTRIBUTING.md", "make bench-check", "CONTRIBUTING bench-check guidance")
		requireContainsFile(t, root, "ARCHITECTURE.md", "[docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md)", "ARCHITECTURE mental-model link")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "make contributor-check", "verification guide contributor-check guidance")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "make bench-check", "verification guide bench-check guidance")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "make verify-release RELEASE_TAG=vX.Y.Z", "verification guide release wrapper guidance")
		requireContainsFile(t, root, "docs/contributor/core-mental-model.md", "normalized policy oracle", "core mental model policy oracle wording")
		requireContainsFile(t, root, "docs/contributor/core-mental-model.md", "Go also enforces preflight and session-level gates", "core mental model Go gate wording")
		requireContainsFile(t, root, "docs/contributor/first-30-minutes.md", "Rust owns normalized policy; Go adds preflight/session gates and mirrors the typed surface", "first-30-minutes policy split wording")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "trusted MCP servers bypass the credential scan", "verification guide trusted MCP bypass wording")
		requireContainsFile(t, root, "docs/contributor/supply-chain-policy.md", "make verify-release RELEASE_TAG=vX.Y.Z", "supply-chain release wrapper guidance")
		requireContainsFile(t, root, "docs/user/faq.md", "make verify-release RELEASE_TAG=vX.Y.Z", "FAQ release wrapper guidance")
		requireContainsFile(t, root, ".github/pull_request_template.md", "make contributor-check", "PR template contributor-check guidance")
	})

	t.Run("workflow_policy_contract", func(t *testing.T) {
		requireFileExists(t, root, "scripts/check_workflow_policy.rb")
		requireContainsFile(t, root, ".github/workflows/actionlint.yml", "ruby scripts/check_workflow_policy.rb", "actionlint banned-trigger guard")
		requireContainsFile(t, root, ".github/workflows/actionlint.yml", "scripts/check_workflow_policy.rb", "actionlint self-test path filter")
		requireContainsFile(t, root, ".github/workflows/ci.yml", "Skip when Rust CI is not required", "ci rust no-op required check")
		requireContainsFile(t, root, ".github/workflows/ci.yml", "Skip when Go CI is not required", "ci go no-op required check")
		requireContainsFile(t, root, ".github/workflows/post-merge.yml", "name: Post-merge Assurance", "post-merge workflow name")
		requireContainsFile(t, root, ".github/workflows/post-merge.yml", "Build artifacts & checksums", "post-merge artifact assurance")
		requireContainsFile(t, root, ".github/workflows/post-merge.yml", "Generate SBOM", "post-merge sbom assurance")
		requireContainsFile(t, root, ".github/workflows/zizmor.yml", "--offline", "zizmor workflow mode")
		requireContainsFile(t, root, "docs/contributor/supply-chain-policy.md", "explicit offline mode in both PR and `main` workflows", "supply-chain zizmor mode")
		requireContainsFile(t, root, "scripts/check_workflow_policy.rb", "BANNED_TRIGGERS = %w[pull_request_target workflow_run].freeze", "workflow policy banned trigger list")
		requireContainsFile(t, root, "scripts/check_workflow_policy.rb", "Dir[\".github/workflows/*.{yml,yaml}\"]", "workflow policy yml/yaml coverage")
		requireWorkflowPolicyFixture(t, root, map[string]string{
			".github/workflows/allowed.yaml": strings.TrimSpace(`
name: allowed
on:
  pull_request:
  push:
`),
			".github/actions/nested/action.yml": strings.TrimSpace(`
name: nested
on:
  workflow_dispatch:
`),
		})
		requireWorkflowPolicyFixtureFailure(t, root, map[string]string{
			".github/workflows/banned.yml": strings.TrimSpace(`
name: banned
on:
  workflow_run:
`),
		}, ".github/workflows/banned.yml: banned workflow trigger(s): workflow_run")
		requireWorkflowPolicyFixtureFailure(t, root, map[string]string{
			".github/workflows/coerced.yml": strings.TrimSpace(`
name: coerced
on:
  pull_request_target:
    branches:
      - main
`),
		}, ".github/workflows/coerced.yml: banned workflow trigger(s): pull_request_target")
	})

	t.Run("release_trust_contract", func(t *testing.T) {
		if _, err := os.Stat(releaseWorkflowPath); err != nil {
			if os.IsNotExist(err) {
				t.Skip("release workflow absent in this repo state")
			}
			t.Fatalf("stat %s: %v", releaseWorkflowPath, err)
		}
		requireContainsFile(t, root, ".github/workflows/release.yml", "uses: sigstore/cosign-installer@", "release workflow installs cosign")
		requireContainsFile(t, root, ".github/workflows/release.yml", "cosign sign-blob --yes", "release workflow signs archives and manifests")
		requireContainsFile(t, root, ".github/workflows/release.yml", "cosign attest-blob --yes", "release workflow emits attestations")
		requireContainsFile(t, root, ".github/workflows/release.yml", "provenance:", "release workflow provenance job")
		requireContainsFile(t, root, ".github/workflows/release.yml", "Verify cosign signatures on every archive", "release workflow verifies archive signatures")
		requireContainsFile(t, root, ".github/workflows/release.yml", "Verify cosign signature on checksums.txt", "release workflow verifies signed checksums")
		requireContainsFile(t, root, ".github/workflows/release.yml", "Verify cosign signature on AIBOM", "release workflow verifies signed aibom")
		requireContainsFile(t, root, ".github/workflows/release.yml", "Verify SLSA provenance on every archive", "release workflow verifies provenance")
		requireContainsFile(t, root, ".github/workflows/release.yml", "environment:\n      name: release", "release workflow requires environment approval")

		requireContainsFile(t, root, "scripts/verify-release.sh", "cosign verify-blob", "verify-release checks cosign signatures")
		requireContainsFile(t, root, "scripts/verify-release.sh", "slsa-verifier verify-artifact", "verify-release checks SLSA provenance")
		requireContainsFile(t, root, "scripts/verify-release.sh", "require_checksum_targets", "verify-release validates checksum targets before hashing")
		requireContainsFile(t, root, "scripts/verify-release.sh", "zero-ML declaration verified", "verify-release validates the AIBOM zero-ML declaration")

		requireContainsFile(t, root, "docs/contributor/supply-chain-policy.md", "signed artifacts, provenance, and SBOM output", "supply-chain policy release trust signals")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "cosign signatures on every archive", "verification guide archive signature guarantee")
		requireContainsFile(t, root, "docs/research/security-verification-guide.md", "SLSA provenance for every archive", "verification guide provenance guarantee")
	})

	t.Run("active_docs_surface", func(t *testing.T) {
		got := collectActiveDocs(t, root)
		want := activeDocAllowlist()
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("active doc allowlist drifted\nwant: %v\n got: %v", want, got)
		}

		requireNotExists(t, root, ".claude/settings.local.json")
		requireNotExists(t, root, "sir.code-workspace")

		for _, rel := range []string{
			"docs/user/README.md",
			"docs/user/quickstart.md",
			"docs/user/credential-scanning.md",
			"docs/contributor/README.md",
			"docs/contributor/branch-protection.md",
			"docs/contributor/architecture-reference.md",
			"docs/contributor/security-engineering-guide.md",
			"docs/contributor/security-engineering-reference.md",
			"docs/contributor/managed-mode-design.md",
			"docs/contributor/runtime-containment-design.md",
			"docs/contributor/secret-lineage-design.md",
			"docs/research/README.md",
			"docs/research/security-architecture-review.md",
		} {
			requireNotExists(t, root, rel)
		}
	})

	t.Run("docs_budgets", func(t *testing.T) {
		total := 0
		for _, rel := range activeDocAllowlist() {
			lines := countLines(readFile(t, root, rel))
			if lines > 250 {
				t.Fatalf("%s has %d lines, want <= 250", rel, lines)
			}
			total += lines
		}
		if total > 3500 {
			t.Fatalf("active docs total %d lines, want <= 3500", total)
		}

		requireMaxLines(t, root, "README.md", 150)
		requireMaxLines(t, root, "CONTRIBUTING.md", 180)
		requireMaxLines(t, root, "ARCHITECTURE.md", 200)
		requireMaxLines(t, root, "docs/user/faq.md", 150)
	})
}

func activeDocAllowlist() []string {
	return []string{
		"ARCHITECTURE.md",
		"CHANGELOG.md",
		"CLAUDE.md",
		"CODE_OF_CONDUCT.md",
		"CONTRIBUTING-AGENTS.md",
		"CONTRIBUTING.md",
		"README.md",
		"SECURITY.md",
		"docs/README.md",
		"docs/contributor/core-mental-model.md",
		"docs/contributor/first-30-minutes.md",
		"docs/contributor/security-engineering-core.md",
		"docs/contributor/supply-chain-policy.md",
		"docs/research/observability-design.md",
		"docs/research/security-verification-guide.md",
		"docs/research/sir-threat-model.md",
		"docs/research/validation-summary.md",
		"docs/user/claude-code-hooks-integration.md",
		"docs/user/codex-support.md",
		"docs/user/faq.md",
		"docs/user/gemini-support.md",
		"docs/user/runtime-security-overview.md",
		"docs/user/siem-integration.md",
	}
}

func collectActiveDocs(t *testing.T, root string) []string {
	t.Helper()

	var docs []string
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read root dir: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".md") {
			docs = append(docs, name)
		}
	}

	err = filepath.Walk(filepath.Join(root, "docs"), func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() || !strings.HasSuffix(path, ".md") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		docs = append(docs, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs dir: %v", err)
	}

	sort.Strings(docs)
	return docs
}

func repoRoot(t *testing.T) string {
	t.Helper()
	var starts []string
	if cwd, err := os.Getwd(); err == nil {
		starts = append(starts, cwd)
	}
	if _, file, _, ok := runtime.Caller(0); ok && filepath.IsAbs(file) {
		starts = append(starts, filepath.Dir(file))
	}
	for _, start := range starts {
		if root := findRepoRoot(start); root != "" {
			return root
		}
	}
	t.Fatalf("could not determine repo root from %q", starts)
	return ""
}

func findRepoRoot(start string) string {
	dir := filepath.Clean(start)
	for {
		if fileExists(filepath.Join(dir, "go.mod")) && fileExists(filepath.Join(dir, "rust-toolchain.toml")) {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func readFile(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func requireFileExists(t *testing.T, root, rel string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
		t.Fatalf("expected %s to exist: %v", rel, err)
	}
}

func requireNotExists(t *testing.T, root, rel string) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
		t.Fatalf("expected %s to stay absent", rel)
	}
}

func requireContainsFile(t *testing.T, root, rel, needle, label string) {
	t.Helper()
	if !strings.Contains(readFile(t, root, rel), needle) {
		t.Fatalf("%s missing expected text %q in %s", label, needle, rel)
	}
}

func requireGeneratedBlock(t *testing.T, root, rel, blockName, expected string) {
	t.Helper()
	body := readFile(t, root, rel)
	begin := "<!-- BEGIN " + blockName + " -->"
	end := "<!-- END " + blockName + " -->"
	start := strings.Index(body, begin)
	if start == -1 {
		t.Fatalf("%s missing begin marker %q", rel, begin)
	}
	start += len(begin)
	finish := strings.Index(body[start:], end)
	if finish == -1 {
		t.Fatalf("%s missing end marker %q", rel, end)
	}
	got := strings.TrimSpace(body[start : start+finish])
	want := strings.TrimSpace(expected)
	if got != want {
		t.Fatalf("%s generated block drifted\nwant:\n%s\n\ngot:\n%s", rel, want, got)
	}
}

func requireWorkflowPolicyFixture(t *testing.T, root string, fixtures map[string]string) {
	t.Helper()
	stdout, stderr, err := runWorkflowPolicyScript(t, root, fixtures)
	if err != nil {
		t.Fatalf("workflow policy fixture failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdout, stderr)
	}
	if !strings.Contains(stdout, "workflow trigger policy OK") {
		t.Fatalf("workflow policy fixture missing success output: %q", stdout)
	}
}

func requireWorkflowPolicyFixtureFailure(t *testing.T, root string, fixtures map[string]string, needle string) {
	t.Helper()
	stdout, stderr, err := runWorkflowPolicyScript(t, root, fixtures)
	if err == nil {
		t.Fatalf("workflow policy fixture unexpectedly passed\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stderr, needle) {
		t.Fatalf("workflow policy fixture missing failure %q\nstdout:\n%s\nstderr:\n%s", needle, stdout, stderr)
	}
}

func runWorkflowPolicyScript(t *testing.T, root string, fixtures map[string]string) (string, string, error) {
	t.Helper()
	tempRoot := t.TempDir()
	for rel, body := range fixtures {
		path := filepath.Join(tempRoot, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(body+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}

	cmd := exec.Command("ruby", filepath.Join(root, "scripts", "check_workflow_policy.rb"))
	cmd.Dir = tempRoot
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func requireMaxLines(t *testing.T, root, rel string, max int) {
	t.Helper()
	lines := countLines(readFile(t, root, rel))
	if lines > max {
		t.Fatalf("%s has %d lines, want <= %d", rel, lines, max)
	}
}

func countLines(body string) int {
	if body == "" {
		return 0
	}
	return len(strings.Split(strings.TrimSuffix(body, "\n"), "\n"))
}

func requireOrderedSubstrings(t *testing.T, body string, parts ...string) {
	t.Helper()
	last := -1
	for _, part := range parts {
		idx := strings.Index(body, part)
		if idx == -1 {
			t.Fatalf("missing expected section %q", part)
		}
		if idx < last {
			t.Fatalf("section %q appeared out of order", part)
		}
		last = idx
	}
}

func releaseSeries(version string) string {
	version = strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return version
	}
	return parts[0] + "." + parts[1] + ".x"
}

func mustFindLineValue(t *testing.T, body, prefix, suffix string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value := strings.TrimPrefix(line, prefix)
		if suffix != "" {
			if !strings.HasSuffix(value, suffix) {
				t.Fatalf("line %q does not end with %q", line, suffix)
			}
			value = strings.TrimSuffix(value, suffix)
		}
		return strings.TrimSpace(value)
	}
	t.Fatalf("prefix %q not found", prefix)
	return ""
}

func mustFindWordAfterPrefix(t *testing.T, body, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(line, prefix))
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			t.Fatalf("prefix %q found but no word after it", prefix)
		}
		return fields[0]
	}
	t.Fatalf("prefix %q not found", prefix)
	return ""
}
