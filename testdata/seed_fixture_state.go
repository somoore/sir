package main

import (
	"encoding/json"
	"flag"
	"log"
	"path/filepath"
	"time"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

func main() {
	var projectRoot string
	var secretSession bool
	var denyAll bool
	var postureHashesJSON string
	var pendingInstallJSON string

	flag.StringVar(&projectRoot, "project-root", "", "fixture project root")
	flag.BoolVar(&secretSession, "secret-session", false, "seed secret session state")
	flag.BoolVar(&denyAll, "deny-all", false, "seed deny-all session state")
	flag.StringVar(&postureHashesJSON, "posture-hashes", "{}", "JSON object of posture hashes")
	flag.StringVar(&pendingInstallJSON, "pending-install", "", "JSON object of pending install state")
	flag.Parse()

	if projectRoot == "" {
		log.Fatal("--project-root is required")
	}

	postureHashes := map[string]string{}
	if err := json.Unmarshal([]byte(postureHashesJSON), &postureHashes); err != nil {
		log.Fatalf("unmarshal posture hashes: %v", err)
	}

	state := &session.State{
		SessionID:             "fixture-test-session",
		ProjectRoot:           projectRoot,
		StartedAt:             time.Date(2026, time.April, 5, 0, 0, 0, 0, time.UTC),
		SecretSession:         secretSession,
		TurnCounter:           1,
		RecentlyReadUntrusted: false,
		PostureHashes:         postureHashes,
		DenyAll:               denyAll,
	}

	if secretSession {
		state.SecretSessionSince = state.StartedAt
		state.ApprovalScope = "turn"
		state.SecretApprovalTurn = state.TurnCounter
	}

	if pendingInstallJSON != "" {
		var pending session.PendingInstall
		if err := json.Unmarshal([]byte(pendingInstallJSON), &pending); err != nil {
			log.Fatalf("unmarshal pending install: %v", err)
		}
		state.PendingInstall = &pending
	}

	if err := state.Save(); err != nil {
		log.Fatalf("save session: %v", err)
	}

	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	if err := lease.DefaultLease().Save(leasePath); err != nil {
		log.Fatalf("save default lease: %v", err)
	}
}
