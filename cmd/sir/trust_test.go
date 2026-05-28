package main

import "testing"

func TestCmdTrust_RoutesByNoun(t *testing.T) {
	pr := seedLease(t)

	cmdTrust(pr, []string{"host", "h.example", "--yes"})
	if l, _ := loadProjectLease(pr); !l.IsApprovedHost("h.example") {
		t.Error("trust host should add an approved host")
	}

	cmdTrust(pr, []string{"mcp", "vault", "--yes"})
	if l, _ := loadProjectLease(pr); !l.IsTrustedMCPServer("vault") {
		t.Error("trust mcp should add a trusted server")
	}

	// Legacy bare form == MCP credential trust.
	cmdTrust(pr, []string{"legacysrv", "--yes"})
	if l, _ := loadProjectLease(pr); !l.IsTrustedMCPServer("legacysrv") {
		t.Error("legacy `trust <server>` should still trust an MCP server")
	}

	// path noun marks a sensitive path; --remove unprotects.
	cmdTrust(pr, []string{"path", "configs/prod.env"})
	l, _ := loadProjectLease(pr)
	found := false
	for _, p := range l.SensitivePaths {
		if p == "configs/prod.env" {
			found = true
		}
	}
	if !found {
		t.Error("trust path should add a sensitive path")
	}
	cmdTrust(pr, []string{"path", "configs/prod.env", "--remove"})
	l, _ = loadProjectLease(pr)
	for _, p := range l.SensitivePaths {
		if p == "configs/prod.env" {
			t.Error("trust path --remove should unprotect the path")
		}
	}
}
