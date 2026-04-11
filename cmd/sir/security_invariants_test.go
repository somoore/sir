package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"testing"

	"github.com/somoore/sir/internal/testsecrets"
	"github.com/somoore/sir/pkg/core"
)

type securityInvariantFixture struct {
	Version           int                    `json:"version"`
	Name              string                 `json:"name"`
	Scenario          string                 `json:"scenario"`
	Description       string                 `json:"description"`
	SensitivePath     string                 `json:"sensitive_path,omitempty"`
	ReadOutput        string                 `json:"read_output,omitempty"`
	EgressCommand     string                 `json:"egress_command,omitempty"`
	DerivedPath       string                 `json:"derived_path,omitempty"`
	PushCommand       string                 `json:"push_command,omitempty"`
	AllowedHosts      []string               `json:"allowed_hosts,omitempty"`
	ToolName          string                 `json:"tool_name,omitempty"`
	ToolInput         map[string]interface{} `json:"tool_input,omitempty"`
	ToolOutput        string                 `json:"tool_output,omitempty"`
	ToolOutputFixture string                 `json:"tool_output_fixture,omitempty"`
	TamperedAgent     string                 `json:"tampered_agent,omitempty"`
	DisabledCommand   string                 `json:"disabled_command,omitempty"`
	Expected          map[string]string      `json:"expected"`
}

func TestSecurityInvariantSuiteV1(t *testing.T) {
	fixtures := loadSecurityInvariantFixtures(t)
	if len(fixtures) == 0 {
		t.Fatal("expected at least one security invariant fixture")
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.Name, func(t *testing.T) {
			switch fixture.Scenario {
			case "secret_read_then_egress":
				runInvariantSecretReadThenEgress(t, fixture)
			case "mcp_credential_leak":
				runInvariantMCPCredentialLeak(t, fixture)
			case "mcp_response_middle_window_injection":
				runInvariantMCPResponseMiddleWindowInjection(t, fixture)
			case "mcp_tainted_sink_gate":
				runInvariantMCPTaintedSinkGate(t, fixture)
			case "hook_tamper_restore":
				runInvariantHookTamperRestore(t, fixture)
			case "managed_mode_refusal":
				runInvariantManagedModeRefusal(t, fixture)
			case "lineage_carrying_push_denial":
				runInvariantLineagePushDenial(t, fixture)
			case "evidence_redaction":
				runInvariantEvidenceRedaction(t, fixture)
			case "runtime_containment_failclosed":
				runInvariantRuntimeContainmentFailclosed(t, fixture)
			case "runtime_degradation_guidance":
				runInvariantRuntimeDegradationGuidance(t, fixture)
			case "runtime_host_control_socket_pivot_prevention":
				runInvariantRuntimeHostControlSocketPivotPrevention(t, fixture)
			case "codex_bash_only_boundary":
				runInvariantCodexBashOnlyBoundary(t, fixture)
			case "exact_destination_policy":
				runInvariantExactDestinationPolicy(t, fixture)
			case "runtime_dns_rebinding_authority":
				runInvariantRuntimeDnsRebindingAuthority(t, fixture)
			case "cross_version_state_compatibility":
				runInvariantCrossVersionStateCompatibility(t, fixture)
			case "cross_version_runtime_compatibility":
				runInvariantCrossVersionRuntimeCompatibility(t, fixture)
			case "runtime_bridge_degradation_compatibility":
				runInvariantRuntimeBridgeDegradationCompatibility(t, fixture)
			case "cross_version_lineage_state_compatibility":
				runInvariantCrossVersionLineageStateCompatibility(t, fixture)
			case "cross_version_ledger_compatibility":
				runInvariantCrossVersionLedgerCompatibility(t, fixture)
			default:
				t.Fatalf("unknown security invariant scenario %q", fixture.Scenario)
			}
		})
	}
}

func loadSecurityInvariantFixtures(t *testing.T) []securityInvariantFixture {
	t.Helper()
	root := repoRoot(t)
	paths, err := filepath.Glob(filepath.Join(root, "testdata", "security-invariants", "v1", "*.json"))
	if err != nil {
		t.Fatalf("glob fixtures: %v", err)
	}
	sort.Strings(paths)

	out := make([]securityInvariantFixture, 0, len(paths))
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read fixture %s: %v", path, err)
		}
		data = bytes.ReplaceAll(data, []byte("__TEST_AWS_ACCESS_KEY__"), []byte(testsecrets.AWSAccessKey()))
		var fixture securityInvariantFixture
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatalf("unmarshal fixture %s: %v", path, err)
		}
		if fixture.Version != 1 {
			t.Fatalf("fixture %s schema version = %d, want 1", path, fixture.Version)
		}
		if fixture.Name == "" || fixture.Scenario == "" {
			t.Fatalf("fixture %s missing name or scenario", path)
		}
		out = append(out, fixture)
	}
	return out
}

func computeLegacyInvariantLedgerHash(entry map[string]interface{}) string {
	h := sha256.New()
	writeField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeField(entry["prev_hash"].(string))
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(entry["index"].(int)))
	h.Write(idxBuf[:])
	writeField(entry["timestamp"].(string))
	writeField(entry["tool_name"].(string))
	writeField(entry["verb"].(string))
	writeField(entry["target"].(string))
	writeField("")
	writeField("")
	writeField("")
	writeField(entry["decision"].(string))
	writeField(entry["reason"].(string))
	writeField("")
	writeField("")
	writeField("")
	if alertType, ok := entry["alert_type"].(string); ok {
		writeField(alertType)
	} else {
		writeField("")
	}
	return hex.EncodeToString(h.Sum(nil))
}

func forceLocalPolicyFallbackForCLI(t *testing.T) {
	t.Helper()
	prev := core.CoreBinaryPath
	core.CoreBinaryPath = "mister-core-not-present-in-tests"
	t.Cleanup(func() { core.CoreBinaryPath = prev })
}

func initInvariantGitRepo(t *testing.T, dir string) {
	t.Helper()
	runInvariantGit(t, dir, "init")
	runInvariantGit(t, dir, "checkout", "-b", "main")
	runInvariantGit(t, dir, "config", "user.email", "sir-tests@example.com")
	runInvariantGit(t, dir, "config", "user.name", "sir tests")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runInvariantGit(t, dir, "add", "README.md")
	runInvariantGit(t, dir, "commit", "-m", "initial commit")
}

func runInvariantGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, string(output))
	}
}
