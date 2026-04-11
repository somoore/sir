// Package lease defines the sir lease model.
// A lease defines what authority the agent has been granted.
package lease

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/policy"
)

// Resource defines a granted resource pattern in the lease.
type Resource struct {
	Pattern      string   `json:"pattern"`
	Permissions  []string `json:"permissions"`
	ResourceKind string   `json:"resource_kind"`
}

// Sink defines a trust boundary for outbound data flow.
type Sink struct {
	Pattern string `json:"pattern"`
	Trust   string `json:"trust"`
	MinRisk string `json:"min_risk"`
}

// Lease is the full lease model. It defines the agent's granted authority.
type Lease struct {
	LeaseID         string `json:"lease_id"`
	Issuer          string `json:"issuer"`
	Principal       string `json:"principal"`
	Mission         string `json:"mission"`
	Mode            string `json:"mode"`
	CompilerCeiling string `json:"compiler_ceiling"`

	Resources []Resource `json:"resources"`

	SensitivePaths          []string `json:"sensitive_paths"`
	SensitivePathExclusions []string `json:"sensitive_path_exclusions"`
	PostureFiles            []string `json:"posture_files"`
	SentinelFilesForInstall []string `json:"sentinel_files_for_installs"`

	AllowedVerbs   []policy.Verb `json:"allowed_verbs"`
	ForbiddenVerbs []policy.Verb `json:"forbidden_verbs"`
	AskVerbs       []policy.Verb `json:"ask_verbs"`

	ApprovedRemotes    []string `json:"approved_remotes"`
	ApprovedHosts      []string `json:"approved_hosts"`
	ApprovedMCPServers []string `json:"approved_mcp_servers"`
	TrustedMCPServers  []string `json:"trusted_mcp_servers,omitempty"` // servers exempt from credential scanning

	Sinks []Sink `json:"sinks"`

	ApprovalRisk    string `json:"approval_risk"`
	AllowDelegation bool   `json:"allow_delegation"`
	ObserveOnly     bool   `json:"observe_only"`
}

// DefaultLease returns the default lease for sir v1.
func DefaultLease() *Lease {
	return &Lease{
		LeaseID:         "default",
		Issuer:          "sir",
		Principal:       "user",
		Mission:         "coding task with secret access control and posture protection",
		Mode:            "guard",
		CompilerCeiling: "R3",

		Resources: []Resource{
			{Pattern: "file://**", Permissions: []string{"read", "write"}, ResourceKind: "file"},
			{Pattern: "shell://workspace", Permissions: []string{"execute"}, ResourceKind: "command"},
			{Pattern: "shell://tests", Permissions: []string{"execute"}, ResourceKind: "command"},
		},

		SensitivePaths: []string{
			".env", ".env.local", ".env.production", ".env.development",
			"*.pem", "*.key", ".aws/*", ".ssh/*",
			".netrc", ".npmrc", "credentials.json", "secrets.*",
			// Extended credential files: docker config, kubernetes config, git
			// credentials store, pip index URL, terraform cloud token, gradle
			// properties, and gh CLI host tokens.
			".docker/config.json", ".kube/config",
			".git-credentials", ".pypirc",
			".terraform/credentials.tfrc.json",
			".gradle/gradle.properties",
			".config/gh/hosts.yml",
		},

		SensitivePathExclusions: []string{
			".env.example", ".env.sample", ".env.template",
			"testdata/**", "fixtures/**", "test/**/*.pem", "test/**/*.key",
		},

		PostureFiles: []string{
			".claude/settings.json",
			"CLAUDE.md", ".mcp.json",
			// Gemini CLI equivalents — guarded for the same reasons as
			// CLAUDE.md and .claude/settings.json: writes to these files
			// can change the agent's instructions or hook configuration.
			".gemini/settings.json",
			"GEMINI.md",
			// Codex CLI equivalents. AGENTS.md is the project-local
			// instructions file. ~/.codex/config.toml holds the feature
			// flags (including codex_hooks) and ~/.codex/hooks.json is
			// sir's own hook registration. A Codex session modifying any
			// of these via apply_patch bypasses PreToolUse entirely, so tamper
			// detection in PostToolUse is the compensating control.
			"AGENTS.md",
			".codex/config.toml",
			".codex/hooks.json",
		},

		SentinelFilesForInstall: []string{
			".claude/settings.json",
			"CLAUDE.md", ".env", ".mcp.json",
			".gemini/settings.json",
			"GEMINI.md",
			"AGENTS.md",
			".codex/config.toml",
			".codex/hooks.json",
		},

		AllowedVerbs: []policy.Verb{
			policy.VerbReadRef, policy.VerbStageWrite, policy.VerbExecuteDryRun, policy.VerbRunTests,
			policy.VerbListFiles, policy.VerbSearchCode, policy.VerbCommit, policy.VerbNetLocal, policy.VerbPushOrigin,
			policy.VerbDelegate, // Agent tool: allowed in clean sessions; blocked by policy if secret session or untrusted read
		},
		ForbiddenVerbs: []policy.Verb{policy.VerbNetExternal},
		AskVerbs:       []policy.Verb{policy.VerbPushRemote, policy.VerbNetAllowlisted, policy.VerbRunEphemeral, policy.VerbMcpUnapproved},

		ApprovedRemotes:    []string{"origin"},
		ApprovedHosts:      []string{"localhost", "127.0.0.1", "::1", "host.docker.internal"},
		ApprovedMCPServers: []string{},

		Sinks: []Sink{
			{Pattern: "file://**", Trust: "trusted", MinRisk: "R0"},
			{Pattern: "shell://workspace", Trust: "trusted", MinRisk: "R0"},
			{Pattern: "git-commit", Trust: "trusted", MinRisk: "R0"},
			{Pattern: "git-push-approved", Trust: "verified_internal", MinRisk: "R2"},
			{Pattern: "git-push-unapproved", Trust: "untrusted", MinRisk: "R4"},
			{Pattern: "net://approved", Trust: "verified_internal", MinRisk: "R1"},
			{Pattern: "net://loopback", Trust: "verified_internal", MinRisk: "R0"},
			{Pattern: "net://external", Trust: "untrusted", MinRisk: "R4"},
			{Pattern: "*", Trust: "untrusted", MinRisk: "R4"},
		},

		ApprovalRisk:    "R3",
		AllowDelegation: true, // clean sessions: allowed; secret/untrusted sessions: still gated by policy
		ObserveOnly:     false,
	}
}

// Load reads a lease from a JSON file.
func Load(path string) (*Lease, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l Lease
	if err := json.Unmarshal(data, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// Save writes the lease to a JSON file.
func (l *Lease) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	tmpFile, err := os.CreateTemp(dir, "lease-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// IsVerbAllowed checks if a verb is in the allowed list.
func (l *Lease) IsVerbAllowed(verb policy.Verb) bool {
	for _, v := range l.AllowedVerbs {
		if v == verb {
			return true
		}
	}
	return false
}

// IsVerbForbidden checks if a verb is in the forbidden list.
func (l *Lease) IsVerbForbidden(verb policy.Verb) bool {
	for _, v := range l.ForbiddenVerbs {
		if v == verb {
			return true
		}
	}
	return false
}

// IsVerbAsk checks if a verb requires user approval.
func (l *Lease) IsVerbAsk(verb policy.Verb) bool {
	for _, v := range l.AskVerbs {
		if v == verb {
			return true
		}
	}
	return false
}

// IsTrustedMCPServer checks if a server name is in the trusted MCP servers list.
// Trusted servers are exempt from credential argument scanning.
func (l *Lease) IsTrustedMCPServer(serverName string) bool {
	for _, s := range l.TrustedMCPServers {
		if s == serverName {
			return true
		}
	}
	return false
}
