package main

import (
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func seedLease(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("SIR_STATE_HOME", home)
	projectRoot := t.TempDir()
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	if err := lease.DefaultLease().Save(leasePath); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
	return projectRoot
}

func TestAllowHost_AddThenRemove(t *testing.T) {
	pr := seedLease(t)
	cmdAllowHostArgs(pr, []string{"api.example.com", "--yes"})
	if l, _ := loadProjectLease(pr); !l.IsApprovedHost("api.example.com") {
		t.Fatal("host should be approved after add")
	}
	cmdAllowHostArgs(pr, []string{"api.example.com", "--remove"})
	if l, _ := loadProjectLease(pr); l.IsApprovedHost("api.example.com") {
		t.Fatal("host should be gone after --remove")
	}
}

func TestAllowHost_RemoveCancelsTTL(t *testing.T) {
	pr := seedLease(t)
	cmdAllowHostArgs(pr, []string{"h.example", "--ttl", "2h", "--yes"})
	l, _ := loadProjectLease(pr)
	if _, ok := l.ApprovedHostExpires["h.example"]; !ok {
		t.Fatal("expected TTL entry after add")
	}
	cmdAllowHostArgs(pr, []string{"h.example", "--remove"})
	l, _ = loadProjectLease(pr)
	if _, ok := l.ApprovedHostExpires["h.example"]; ok {
		t.Fatal("TTL should be cancelled after --remove")
	}
	if l.IsApprovedHost("h.example") {
		t.Fatal("host should be gone after --remove")
	}
}

func TestAllowRemote_AddThenRemove(t *testing.T) {
	pr := seedLease(t)
	cmdAllowRemoteArgs(pr, []string{"backup", "--yes"})
	l, _ := loadProjectLease(pr)
	found := false
	for _, r := range l.ApprovedRemotes {
		if r == "backup" {
			found = true
		}
	}
	if !found {
		t.Fatal("remote should be approved after add")
	}
	cmdAllowRemoteArgs(pr, []string{"backup", "--remove"})
	l, _ = loadProjectLease(pr)
	for _, r := range l.ApprovedRemotes {
		if r == "backup" {
			t.Fatal("remote should be gone after --remove")
		}
	}
}

func TestTrust_AddThenRemove(t *testing.T) {
	pr := seedLease(t)
	cmdTrustMCPArgs(pr, []string{"vault", "--yes"})
	if l, _ := loadProjectLease(pr); !l.IsTrustedMCPServer("vault") {
		t.Fatal("server should be trusted after add")
	}
	cmdTrustMCPArgs(pr, []string{"vault", "--remove"})
	if l, _ := loadProjectLease(pr); l.IsTrustedMCPServer("vault") {
		t.Fatal("trust should be revoked after --remove")
	}
}
