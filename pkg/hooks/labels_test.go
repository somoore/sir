package hooks

import (
	"testing"

	"github.com/somoore/sir/pkg/lease"
)

func TestIsSensitivePath(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Sensitive paths that MUST be caught
		{".env is sensitive", ".env", true},
		{".env.local is sensitive", ".env.local", true},
		{".env.production is sensitive", ".env.production", true},
		{".env.development is sensitive", ".env.development", true},
		{"cert.pem is sensitive", "cert.pem", true},
		{"server.key is sensitive", "server.key", true},
		{".aws/credentials is sensitive", ".aws/credentials", true},
		{".aws/config is sensitive", ".aws/config", true},
		{".ssh/id_rsa is sensitive", ".ssh/id_rsa", true},
		{".ssh/id_ed25519 is sensitive", ".ssh/id_ed25519", true},
		{".netrc is sensitive", ".netrc", true},
		{"credentials.json is sensitive", "credentials.json", true},
		{"nested cert is sensitive", "config/ssl/server.pem", true},
		{"nested key is sensitive", "certs/private.key", true},

		// Exclusions that MUST NOT be caught
		{".env.example is excluded", ".env.example", false},
		{".env.sample is excluded", ".env.sample", false},
		{".env.template is excluded", ".env.template", false},
		{"testdata pem is excluded", "testdata/cert.pem", false},
		{"testdata nested pem is excluded", "testdata/ssl/server.pem", false},
		{"fixtures key is excluded", "fixtures/test.key", false},
		{"test dir pem is excluded", "test/certs/ca.pem", false},
		{"test dir key is excluded", "test/ssl/server.key", false},

		// Normal files that MUST NOT be caught
		{"go source is not sensitive", "src/main.go", false},
		{"README is not sensitive", "README.md", false},
		{"Dockerfile is not sensitive", "Dockerfile", false},
		{"go.mod is not sensitive", "go.mod", false},
		{"package.json is not sensitive", "package.json", false},
		{"Makefile is not sensitive", "Makefile", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsSensitivePath(tc.path, l)
			if got != tc.expected {
				t.Errorf("IsSensitivePath(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

func TestIsPostureFile(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Posture files
		{"claude settings is posture", ".claude/settings.json", true},
		{"CLAUDE.md is posture", "CLAUDE.md", true},
		{".mcp.json is posture", ".mcp.json", true},
		// Not posture files
		{"src file is not posture", "src/main.go", false},
		{"package.json is not posture", "package.json", false},
		{"README is not posture", "README.md", false},
		{".env is not posture", ".env", false},
		{"tsconfig is not posture", "tsconfig.json", false},
		{"random claude path is not posture", ".claude/random.txt", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsPostureFile(tc.path, l)
			if got != tc.expected {
				t.Errorf("IsPostureFile(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

func TestClassifyNetworkDest(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name     string
		dest     string
		expected string
	}{
		// Loopback
		{"localhost is loopback", "http://localhost:3000", "loopback"},
		{"127.0.0.1 is loopback", "http://127.0.0.1:8080", "loopback"},
		{"::1 is loopback", "::1", "loopback"},
		{"bare localhost is loopback", "localhost:3000", "loopback"},
		{"bare 127.0.0.1 is loopback", "127.0.0.1:8080", "loopback"},

		// External
		{"example.com is external", "https://example.com", "external"},
		{"api.evil.com is external", "https://api.evil.com/collect", "external"},
		{"10.0.0.1 is external (RFC1918 not auto-trusted)", "http://10.0.0.1:3000", "external"},
		{"192.168.1.1 is external (RFC1918 not auto-trusted)", "http://192.168.1.1", "external"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyNetworkDest(tc.dest, l)
			if got != tc.expected {
				t.Errorf("ClassifyNetworkDest(%q) = %q, want %q", tc.dest, got, tc.expected)
			}
		})
	}
}

func TestClassifyNetworkDestWithCustomApprovedHost(t *testing.T) {
	l := lease.DefaultLease()
	l.ApprovedHosts = append(l.ApprovedHosts, "api.internal.corp")

	tests := []struct {
		name     string
		dest     string
		expected string
	}{
		{"approved corp host", "https://api.internal.corp/data", "approved"},
		{"still external", "https://evil.com/data", "external"},
		{"still loopback", "http://localhost:3000", "loopback"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyNetworkDest(tc.dest, l)
			if got != tc.expected {
				t.Errorf("ClassifyNetworkDest(%q) = %q, want %q", tc.dest, got, tc.expected)
			}
		})
	}
}

func TestClassifyGitRemote(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name     string
		remote   string
		approved bool
	}{
		{"origin is approved", "origin", true},
		{"upstream is not approved", "upstream", false},
		{"evil-fork is not approved", "evil-fork", false},
		{"my-fork is not approved", "my-fork", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyGitRemote("git push "+tc.remote+" main", l) == "approved"
			if got != tc.approved {
				t.Errorf("IsApprovedRemote(%q) = %v, want %v", tc.remote, got, tc.approved)
			}
		})
	}
}

func TestLabelsForPath(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name                string
		path                string
		expectedSensitivity string
	}{
		{".env gets secret label", ".env", "secret"},
		{".env.local gets secret label", ".env.local", "secret"},
		{"cert.pem gets secret label", "cert.pem", "secret"},
		{".env.example gets internal label (excluded)", ".env.example", "internal"},
		{"testdata pem gets internal label (excluded)", "testdata/cert.pem", "internal"},
		{"src/main.go gets internal label", "src/main.go", "internal"},
		{"README.md gets internal label", "README.md", "internal"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			labels := LabelsForPath(tc.path, l)
			if len(labels) == 0 {
				t.Fatal("expected at least one label")
			}
			if labels[0].Sensitivity != tc.expectedSensitivity {
				t.Errorf("LabelsForPath(%q): sensitivity = %q, want %q",
					tc.path, labels[0].Sensitivity, tc.expectedSensitivity)
			}
		})
	}
}

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		path     string
		expected bool
	}{
		{"exact match", ".env", ".env", true},
		{"exact no match", ".env", ".env.local", false},
		{"wildcard ext pem", "*.pem", "cert.pem", true},
		{"wildcard ext nested pem", "*.pem", "config/ssl/cert.pem", true},
		{"wildcard ext no match", "*.pem", "cert.crt", false},
		{"dir wildcard", ".aws/*", ".aws/credentials", true},
		{"dir wildcard no match", ".aws/*", ".gcp/credentials", false},
		{"double star prefix", "testdata/**", "testdata/cert.pem", true},
		{"double star nested", "testdata/**", "testdata/ssl/cert.pem", true},
		{"double star no match", "testdata/**", "src/cert.pem", false},
		{"complex glob pem", "test/**/*.pem", "test/certs/ca.pem", true},
		{"complex glob no match", "test/**/*.pem", "src/certs/ca.pem", false},
		{"secrets wildcard", "secrets.*", "secrets.json", true},
		{"secrets yaml", "secrets.*", "secrets.yaml", true},
		{"secrets no match", "secrets.*", "secret.json", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := MatchGlob(tc.pattern, tc.path)
			if got != tc.expected {
				t.Errorf("MatchGlob(%q, %q) = %v, want %v",
					tc.pattern, tc.path, got, tc.expected)
			}
		})
	}
}

func TestIsSensitivePathAbsoluteAndTraversal(t *testing.T) {
	l := lease.DefaultLease()

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Absolute path bypass (Claude Code sends absolute paths)
		{"absolute .env", "/home/user/project/.env", true},
		{"absolute .aws/credentials", "/home/user/.aws/credentials", true},
		{"absolute *.pem", "/home/user/project/config/server.pem", true},
		{"absolute .ssh/id_rsa", "/home/user/.ssh/id_rsa", true},
		{"absolute .kube/config", "/home/user/.kube/config", true},
		// Traversal bypass (relative paths that escape project root)
		{"traversal .env", "../../.env", true},
		{"traversal .aws", "../../.aws/credentials", true},
		{"nested .env in project", "subdir/.env", true},
		// Should still NOT match
		{"absolute normal file", "/home/user/project/main.go", false},
		{"absolute README", "/home/user/project/README.md", false},
		{"absolute .env.example excluded", "/home/user/project/.env.example", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsSensitivePath(tc.path, l)
			if got != tc.expected {
				t.Errorf("IsSensitivePath(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}
