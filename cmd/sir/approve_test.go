package main

import (
	"testing"

	"github.com/somoore/sir/pkg/ledger"
)

func TestLeaseableApproval(t *testing.T) {
	cases := []struct {
		name       string
		entry      ledger.Entry
		wantKind   string
		wantTarget string
		wantOK     bool
	}{
		{"external host", ledger.Entry{Verb: "net_external", Target: "https://api.example.com/v1/x?token=abc"}, "host", "api.example.com", true},
		{"allowlisted host", ledger.Entry{Verb: "net_allowlisted", Target: "registry.npmjs.org:443"}, "host", "registry.npmjs.org", true},
		{"push origin", ledger.Entry{Verb: "push_origin", Target: "git@github.com:o/r"}, "remote", "origin", true},
		{"mcp onboarding", ledger.Entry{Verb: "mcp_onboarding", ToolName: "mcp__github__create_issue"}, "mcp", "github", true},
		// Security-sensitive intents are never auto-leased.
		{"secret read", ledger.Entry{Verb: "read_ref", Target: ".env", Sensitivity: "secret"}, "", "", false},
		{"dns lookup", ledger.Entry{Verb: "dns_lookup", Target: "evil.example"}, "", "", false},
		{"env read", ledger.Entry{Verb: "env_read", Target: "printenv"}, "", "", false},
		{"persistence", ledger.Entry{Verb: "persistence", Target: "npm i foo"}, "", "", false},
		{"posture write", ledger.Entry{Verb: "stage_write", Target: ".claude/settings.json"}, "", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			kind, target, ok := leaseableApproval(c.entry)
			if ok != c.wantOK || kind != c.wantKind || target != c.wantTarget {
				t.Errorf("leaseableApproval = (%q,%q,%v), want (%q,%q,%v)", kind, target, ok, c.wantKind, c.wantTarget, c.wantOK)
			}
		})
	}
}

func TestApproveHostFromTarget(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com/x":     "api.example.com",
		"http://user:pass@h.example:80": "h.example",
		"bare.host.example":             "bare.host.example",
		"host.example:8443":             "host.example",
		"":                              "",
	}
	for in, want := range cases {
		if got := approveHostFromTarget(in); got != want {
			t.Errorf("approveHostFromTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApproveMCPServer(t *testing.T) {
	cases := map[string]string{
		"mcp__github__create_issue": "github",
		"mcp__postgres":             "postgres",
		"Bash":                      "",
		"":                          "",
	}
	for in, want := range cases {
		if got := approveMCPServer(in); got != want {
			t.Errorf("approveMCPServer(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHostLeaseArgs_DefaultsTTL(t *testing.T) {
	got := hostLeaseArgs("h.example", nil)
	if len(got) != 3 || got[0] != "h.example" || got[1] != "--ttl" || got[2] != "15m" {
		t.Errorf("hostLeaseArgs default = %v, want [h.example --ttl 15m]", got)
	}
	got = hostLeaseArgs("h.example", []string{"--ttl", "2h"})
	if len(got) != 3 || got[2] != "2h" {
		t.Errorf("hostLeaseArgs with ttl = %v, want [h.example --ttl 2h]", got)
	}
}

func TestApproveForcesGrant(t *testing.T) {
	if !approveForcesGrant([]string{"--once"}) || !approveForcesGrant([]string{"--session"}) {
		t.Error("--once/--session should force grant")
	}
	if approveForcesGrant([]string{"--ttl", "1h"}) {
		t.Error("--ttl alone should not force grant")
	}
}
