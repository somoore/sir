package lease

import (
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

func TestDefaultLease_NoZeroZeroZeroZero(t *testing.T) {
	l := DefaultLease()
	for _, host := range l.ApprovedHosts {
		if host == "0.0.0.0" {
			t.Error("DefaultLease().ApprovedHosts must not contain '0.0.0.0' — it binds to all interfaces and is not a safe loopback")
		}
	}
}

func TestDefaultLease_HasIPv6Loopback(t *testing.T) {
	l := DefaultLease()
	found := false
	for _, host := range l.ApprovedHosts {
		if host == "::1" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DefaultLease().ApprovedHosts must contain '::1' (IPv6 loopback); got %v", l.ApprovedHosts)
	}
}

func TestDefaultLease_ApprovedMCPServersIsEmptyNotNil(t *testing.T) {
	l := DefaultLease()
	if l.ApprovedMCPServers == nil {
		t.Error("DefaultLease().ApprovedMCPServers must be an empty slice, not nil")
	}
	if len(l.ApprovedMCPServers) != 0 {
		t.Errorf("DefaultLease().ApprovedMCPServers should be empty by default, got %v", l.ApprovedMCPServers)
	}
}

func TestDefaultLease_HasLocalhostAndIPv4Loopback(t *testing.T) {
	l := DefaultLease()
	required := []string{"localhost", "127.0.0.1"}
	hostSet := make(map[string]bool, len(l.ApprovedHosts))
	for _, h := range l.ApprovedHosts {
		hostSet[h] = true
	}
	for _, r := range required {
		if !hostSet[r] {
			t.Errorf("DefaultLease().ApprovedHosts is missing required loopback %q; got %v", r, l.ApprovedHosts)
		}
	}
}

func TestDefaultLease_DockerHostnamePresent(t *testing.T) {
	l := DefaultLease()
	found := false
	for _, host := range l.ApprovedHosts {
		if host == "host.docker.internal" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DefaultLease().ApprovedHosts should contain 'host.docker.internal' for container workflows; got %v", l.ApprovedHosts)
	}
}

func TestDefaultLease_HasSensitivePaths(t *testing.T) {
	l := DefaultLease()
	if len(l.SensitivePaths) == 0 {
		t.Error("DefaultLease().SensitivePaths must not be empty")
	}
	// Spot-check critical paths
	required := []string{".env", "*.pem", "*.key", ".aws/*", ".ssh/*"}
	pathSet := make(map[string]bool, len(l.SensitivePaths))
	for _, p := range l.SensitivePaths {
		pathSet[p] = true
	}
	for _, r := range required {
		if !pathSet[r] {
			t.Errorf("DefaultLease().SensitivePaths missing critical path %q", r)
		}
	}
}

func TestDefaultLease_ExtendedCredentialFiles(t *testing.T) {
	// The default lease must include the extended credential file set:
	// docker config, kubernetes config, git credentials store, pip index URL,
	// terraform cloud token, gradle properties, and gh CLI host tokens.
	l := DefaultLease()
	pathSet := make(map[string]bool, len(l.SensitivePaths))
	for _, p := range l.SensitivePaths {
		pathSet[p] = true
	}
	extended := []string{
		".npmrc", ".docker/config.json", ".kube/config",
		".git-credentials", ".pypirc",
		".terraform/credentials.tfrc.json",
		".gradle/gradle.properties",
		".config/gh/hosts.yml",
	}
	for _, e := range extended {
		if !pathSet[e] {
			t.Errorf("DefaultLease().SensitivePaths missing extended credential file %q", e)
		}
	}
}

func TestDefaultLease_HasExclusions(t *testing.T) {
	l := DefaultLease()
	if len(l.SensitivePathExclusions) == 0 {
		t.Error("DefaultLease().SensitivePathExclusions must not be empty")
	}
	// Check that .env.example is in the exclusions
	found := false
	for _, e := range l.SensitivePathExclusions {
		if e == ".env.example" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("DefaultLease().SensitivePathExclusions must contain '.env.example'; got %v", l.SensitivePathExclusions)
	}
}

func TestDefaultLease_HasPostureFiles(t *testing.T) {
	l := DefaultLease()
	if len(l.PostureFiles) == 0 {
		t.Error("DefaultLease().PostureFiles must not be empty")
	}
	required := []string{".claude/settings.json", "CLAUDE.md"}
	pfSet := make(map[string]bool, len(l.PostureFiles))
	for _, p := range l.PostureFiles {
		pfSet[p] = true
	}
	for _, r := range required {
		if !pfSet[r] {
			t.Errorf("DefaultLease().PostureFiles missing critical file %q", r)
		}
	}
}

func TestDefaultLease_ApprovedRemotes(t *testing.T) {
	l := DefaultLease()
	if len(l.ApprovedRemotes) == 0 {
		t.Error("DefaultLease().ApprovedRemotes must not be empty")
	}
	if l.ApprovedRemotes[0] != "origin" {
		t.Errorf("first approved remote should be 'origin', got %q", l.ApprovedRemotes[0])
	}
}

func TestDefaultLease_VerbClassifications(t *testing.T) {
	l := DefaultLease()

	allowedVerbs := []policy.Verb{
		policy.VerbReadRef,
		policy.VerbStageWrite,
		policy.VerbExecuteDryRun,
		policy.VerbRunTests,
		policy.VerbCommit,
	}
	for _, v := range allowedVerbs {
		if !l.IsVerbAllowed(v) {
			t.Errorf("verb %q should be in allowed_verbs", v)
		}
	}

	forbiddenVerbs := []policy.Verb{policy.VerbNetExternal}
	for _, v := range forbiddenVerbs {
		if !l.IsVerbForbidden(v) {
			t.Errorf("verb %q should be in forbidden_verbs", v)
		}
	}

	askVerbs := []policy.Verb{policy.VerbRunEphemeral}
	for _, v := range askVerbs {
		if !l.IsVerbAsk(v) {
			t.Errorf("verb %q should be in ask_verbs", v)
		}
	}
}

func TestLease_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	leasePath := tmpDir + "/lease.json"

	l := DefaultLease()
	if err := l.Save(leasePath); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(leasePath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.LeaseID != l.LeaseID {
		t.Errorf("lease ID: got %q, want %q", loaded.LeaseID, l.LeaseID)
	}
	if len(loaded.SensitivePaths) != len(l.SensitivePaths) {
		t.Errorf("sensitive paths count: got %d, want %d", len(loaded.SensitivePaths), len(l.SensitivePaths))
	}
	if len(loaded.ApprovedHosts) != len(l.ApprovedHosts) {
		t.Errorf("approved hosts count: got %d, want %d", len(loaded.ApprovedHosts), len(l.ApprovedHosts))
	}
	if len(loaded.ApprovedMCPServers) != len(l.ApprovedMCPServers) {
		t.Errorf("approved MCP servers count: got %d, want %d", len(loaded.ApprovedMCPServers), len(l.ApprovedMCPServers))
	}
}

func TestLease_IsVerbAllowed_NotInList(t *testing.T) {
	l := DefaultLease()
	if l.IsVerbAllowed(policy.Verb("nonexistent_verb")) {
		t.Error("nonexistent verb should not be allowed")
	}
}

func TestLease_IsVerbForbidden_NotInList(t *testing.T) {
	l := DefaultLease()
	if l.IsVerbForbidden(policy.VerbReadRef) {
		t.Error("read_ref should not be in forbidden list")
	}
}

func TestLease_IsVerbAsk_NotInList(t *testing.T) {
	l := DefaultLease()
	if l.IsVerbAsk(policy.VerbReadRef) {
		t.Error("read_ref should not be in ask list")
	}
}
