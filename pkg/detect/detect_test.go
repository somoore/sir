package detect

import "testing"

func TestClassify_SilentOnNormalCoding(t *testing.T) {
	// Routine reads, edits, tests, commits, list/search, loopback: no
	// detection should fire — this is the quiet path that keeps sir invisible.
	quiet := []Signal{
		{Verb: "read_ref", Verdict: "allow"},
		{Verb: "stage_write", Verdict: "allow"},
		{Verb: "run_tests", Verdict: "allow"},
		{Verb: "commit", Verdict: "allow"},
		{Verb: "list_files", Verdict: "allow"},
		{Verb: "search_code", Verdict: "allow"},
		{Verb: "net_local", Verdict: "allow"},
		{Verb: "net_external", Verdict: "allow"}, // allowed egress, no secret context
		{Verb: "push_origin", Verdict: "allow"},
	}
	for _, s := range quiet {
		if d, ok := Classify(s); ok {
			t.Errorf("verb %q verdict %q: expected silent, got detection %s", s.Verb, s.Verdict, d.ID)
		}
	}
}

func TestClassify_Detections(t *testing.T) {
	tests := []struct {
		name      string
		sig       Signal
		wantID    ID
		wantSev   Severity
		wantRoute Route
	}{
		{
			name:      "secret to external egress, known host -> SIEM",
			sig:       Signal{Verb: "net_external", Verdict: "deny", SecretSession: true},
			wantID:    SecretToExternalEgress,
			wantSev:   SeverityHigh,
			wantRoute: RouteSIEM,
		},
		{
			name:      "secret to external egress, unusual host -> Slack",
			sig:       Signal{Verb: "net_external", Verdict: "deny", SecretSession: true, Unusual: true},
			wantID:    SecretToExternalEgress,
			wantSev:   SeverityHigh,
			wantRoute: RouteSlack,
		},
		{
			name:      "secret-derived file to external egress",
			sig:       Signal{Verb: "dns_lookup", Verdict: "ask", DerivedFromSecret: true},
			wantID:    SecretToExternalEgress,
			wantRoute: RouteSIEM,
		},
		{
			name:      "secret to push remote",
			sig:       Signal{Verb: "push_remote", Verdict: "deny", SecretSession: true},
			wantID:    SecretToPushRemote,
			wantRoute: RouteSIEM,
		},
		{
			name:      "secret to push, repeated -> Slack",
			sig:       Signal{Verb: "push_remote", Verdict: "deny", SecretSession: true, RepeatedCount: 2},
			wantID:    SecretToPushRemote,
			wantRoute: RouteSlack,
		},
		{
			name:      "mcp injection alert type",
			sig:       Signal{Verb: "mcp_unapproved", Verdict: "deny", AlertType: "mcp_injection"},
			wantID:    MCPInjectionThenAction,
			wantRoute: RouteSlack,
		},
		{
			name:      "pending injection then blocked action",
			sig:       Signal{Verb: "net_external", Verdict: "ask", InjectionAlert: true},
			wantID:    MCPInjectionThenAction,
			wantRoute: RouteSlack,
		},
		{
			name:      "new mcp server via onboarding verb",
			sig:       Signal{Verb: "mcp_onboarding", Verdict: "ask"},
			wantID:    NewMCPServerUsed,
			wantSev:   SeverityMedium,
			wantRoute: RouteSIEM,
		},
		{
			name:      "new mcp server via flag",
			sig:       Signal{Verb: "mcp_unapproved", Verdict: "allow", NewMCPServer: true},
			wantID:    NewMCPServerUsed,
			wantRoute: RouteSIEM,
		},
		{
			name:      "mcp binary drift",
			sig:       Signal{Verb: "mcp_binary_drift", Verdict: "deny", AlertType: "mcp_binary_drift"},
			wantID:    MCPBinaryOrConfigDrift,
			wantRoute: RouteSlack,
		},
		{
			name:      "posture tamper restored",
			sig:       Signal{Verb: "stage_write", Verdict: "deny", AlertType: "config_change_posture", TamperRestored: true},
			wantID:    AgentPostureTamper,
			wantRoute: RouteSlack,
		},
		{
			name:      "hook tamper unrestored -> control plane failure",
			sig:       Signal{Verb: "sir_self", Verdict: "deny", AlertType: "hook_tamper", TamperRestored: false},
			wantID:    ControlPlaneIntegrityFailure,
			wantRoute: RouteSlack,
		},
		{
			name:      "deny-all posture -> control plane failure",
			sig:       Signal{Verb: "read_ref", Verdict: "deny", DenyAll: true},
			wantID:    ControlPlaneIntegrityFailure,
			wantRoute: RouteSlack,
		},
		{
			name:      "package install posture mutation",
			sig:       Signal{Verb: "persistence", Verdict: "ask", PostureMutation: true},
			wantID:    PackageInstallPostureMutation,
			wantRoute: RouteSlack,
		},
		{
			name:      "repeated denied intent",
			sig:       Signal{Verb: "net_external", Verdict: "deny", RepeatedCount: 3},
			wantID:    RepeatedDeniedIntent,
			wantSev:   SeverityLow,
			wantRoute: RouteLocal,
		},
		{
			name:      "credential in tool output",
			sig:       Signal{Verb: "mcp_credential_leak", Verdict: "deny", AlertType: "credential_in_output"},
			wantID:    CredentialInToolOutput,
			wantRoute: RouteSlack,
		},
		{
			name:   "observe-mode would_deny still detects",
			sig:    Signal{Verb: "net_external", Verdict: "would_deny", SecretSession: true},
			wantID: SecretToExternalEgress,
		},
		{
			name:      "mcp change then privileged egress (even allowed)",
			sig:       Signal{Verb: "net_external", Verdict: "allow", RecentMCPChange: true},
			wantID:    MCPChangeThenPrivilegedUse,
			wantSev:   SeverityHigh,
			wantRoute: RouteSlack,
		},
		{
			name:      "mcp change then push",
			sig:       Signal{Verb: "push_remote", Verdict: "allow", RecentMCPChange: true},
			wantID:    MCPChangeThenPrivilegedUse,
			wantRoute: RouteSlack,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, ok := Classify(tt.sig)
			if !ok {
				t.Fatalf("expected detection %s, got none", tt.wantID)
			}
			if d.ID != tt.wantID {
				t.Fatalf("got ID %s, want %s", d.ID, tt.wantID)
			}
			if tt.wantSev != "" && d.Severity != tt.wantSev {
				t.Errorf("got severity %s, want %s", d.Severity, tt.wantSev)
			}
			if tt.wantRoute != RouteSilent && d.Route != tt.wantRoute {
				t.Errorf("got route %s, want %s", d.Route, tt.wantRoute)
			}
		})
	}
}

func TestClassify_SuspicionPromotesRoute(t *testing.T) {
	// A secret egress that is SIEM-routed normally escalates to Slack under
	// suspicion — without changing the detection ID or severity.
	base, ok := Classify(Signal{Verb: "net_external", Verdict: "deny", SecretSession: true})
	if !ok || base.Route != RouteSIEM {
		t.Fatalf("baseline route = %v ok=%v, want SIEM", base.Route, ok)
	}
	susp, ok := Classify(Signal{Verb: "net_external", Verdict: "deny", SecretSession: true, Suspicious: true})
	if !ok || susp.ID != base.ID || susp.Route != RouteSlack {
		t.Fatalf("suspicious route = %v id=%v, want Slack same id", susp.Route, susp.ID)
	}
	// Repeated-denied (Local) promotes to SIEM under suspicion, not Slack —
	// repeated denials stay off the security channel.
	rep, ok := Classify(Signal{Verb: "net_external", Verdict: "deny", RepeatedCount: 2, Suspicious: true})
	if !ok || rep.ID != RepeatedDeniedIntent || rep.Route != RouteSIEM {
		t.Fatalf("suspicious repeated route = %v id=%v, want SIEM repeated_denied_intent", rep.Route, rep.ID)
	}
	// Suspicion never manufactures a detection on a clean allow.
	if _, ok := Classify(Signal{Verb: "read_ref", Verdict: "allow", Suspicious: true}); ok {
		t.Error("suspicion must not create a detection on a clean allow")
	}
}

func TestClassify_MCPChangeScopedToPrivilegedVerbs(t *testing.T) {
	// A recent MCP change does not flag routine reads/writes/tests — only
	// privileged authority use.
	for _, verb := range []string{"read_ref", "stage_write", "run_tests", "commit", "list_files"} {
		if d, ok := Classify(Signal{Verb: verb, Verdict: "allow", RecentMCPChange: true}); ok {
			t.Errorf("verb %q with recent MCP change should stay silent, got %s", verb, d.ID)
		}
	}
}

func TestClassify_SeverityOrdering(t *testing.T) {
	// When both a control-plane failure and a secret-egress condition hold,
	// the more severe control-plane detection wins.
	d, ok := Classify(Signal{Verb: "net_external", Verdict: "deny", SecretSession: true, DenyAll: true})
	if !ok || d.ID != ControlPlaneIntegrityFailure {
		t.Fatalf("expected control-plane failure to dominate, got %v ok=%v", d.ID, ok)
	}
}

func TestCatalog_CoversEveryID(t *testing.T) {
	ids := AllIDs()
	// The ten DoD-required detection IDs are a stable contract; additional
	// compound detections may extend the set.
	required := []ID{
		SecretToExternalEgress, SecretToPushRemote, MCPInjectionThenAction,
		NewMCPServerUsed, MCPBinaryOrConfigDrift, AgentPostureTamper,
		PackageInstallPostureMutation, RepeatedDeniedIntent, CredentialInToolOutput,
		ControlPlaneIntegrityFailure,
	}
	for _, req := range required {
		if !Valid(req) {
			t.Errorf("required detection ID %s missing from catalog", req)
		}
	}
	if len(ids) < len(required) {
		t.Fatalf("expected at least %d detection IDs, got %d", len(required), len(ids))
	}
	for _, id := range ids {
		m, ok := Lookup(id)
		if !ok {
			t.Errorf("id %s missing from catalog", id)
			continue
		}
		if m.ID != id {
			t.Errorf("catalog entry for %s has mismatched ID %s", id, m.ID)
		}
		if m.Title == "" || m.What == "" || m.Why == "" || m.NextStep == "" {
			t.Errorf("id %s has incomplete narrative metadata", id)
		}
		if !Valid(id) {
			t.Errorf("id %s reported invalid", id)
		}
	}
	if len(Catalog()) != len(ids) {
		t.Errorf("Catalog length %d != AllIDs length %d", len(Catalog()), len(ids))
	}
}

func TestRoute_String(t *testing.T) {
	cases := map[Route]string{
		RouteSilent: "silent",
		RouteLocal:  "local",
		RouteSIEM:   "siem",
		RouteSlack:  "slack",
	}
	for r, want := range cases {
		if got := r.String(); got != want {
			t.Errorf("Route(%d).String() = %q, want %q", r, got, want)
		}
	}
}
