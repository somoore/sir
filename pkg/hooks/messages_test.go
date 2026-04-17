package hooks

import (
	"os"
	"strings"
	"testing"
	"time"

	hookmessages "github.com/somoore/sir/pkg/hooks/messages"
)

func init() {
	// Disable colors for deterministic test output
	os.Setenv("NO_COLOR", "1")
}

// assertContains checks that msg contains all specified substrings.
func assertContains(t *testing.T, funcName, msg string, substrs ...string) {
	t.Helper()
	for _, s := range substrs {
		if !strings.Contains(msg, s) {
			t.Errorf("%s: missing expected substring %q\n\nFull message:\n%s", funcName, s, msg)
		}
	}
}

// assertNotContains checks that msg does NOT contain any of the specified substrings.
func assertNotContains(t *testing.T, funcName, msg string, substrs ...string) {
	t.Helper()
	for _, s := range substrs {
		if strings.Contains(msg, s) {
			t.Errorf("%s: should not contain %q\n\nFull message:\n%s", funcName, s, msg)
		}
	}
}

func TestFormatBlock_WhatWhyHow(t *testing.T) {
	msg := FormatBlock("network request to evil.com", "session carries secrets", "sir unlock")
	// WHAT
	assertContains(t, "FormatBlock", msg, "\u00d7 deny", "network request to evil.com")
	// WHY
	assertContains(t, "FormatBlock", msg, "reason:", "session carries secrets")
	// HOW
	assertContains(t, "FormatBlock", msg, "fix:", "sir unlock")
	// Details hint
	assertContains(t, "FormatBlock", msg, "sir explain --last")
}

func TestFormatAsk_WhatWhyHow(t *testing.T) {
	msg := FormatAsk("Write .claude/hooks.json", "posture file", "requires approval")
	// WHAT
	assertContains(t, "FormatAsk", msg, "? ask", "Write .claude/hooks.json")
	// WHY
	assertContains(t, "FormatAsk", msg, "reason:", "posture file")
	// consequence
	assertContains(t, "FormatAsk", msg, "requires approval")
	// Details hint
	assertContains(t, "FormatAsk", msg, "sir explain --last")
}

func TestFormatAsk_EmptyConsequence(t *testing.T) {
	msg := FormatAsk("action", "reason", "")
	assertContains(t, "FormatAsk", msg, "reason:", "reason")
	assertContains(t, "FormatAsk", msg, "sir explain --last")
}

func TestFormatAskSensitive_WhatWhyHow(t *testing.T) {
	msg := FormatAskSensitive(".env", "turn")
	// WHAT
	assertContains(t, "FormatAskSensitive", msg, "? ask", "Read", ".env")
	// WHY
	assertContains(t, "FormatAskSensitive", msg, "reason:", "credentials", "leaks")
	// HOW (after approval)
	assertContains(t, "FormatAskSensitive", msg, "sir allow-host", "sir unlock")
	// Details hint
	assertContains(t, "FormatAskSensitive", msg, "sir explain --last")
	// No secret content
	assertNotContains(t, "FormatAskSensitive", msg, "API_KEY", "password", "token")
}

func TestFormatFatal_WhatWhyHow(t *testing.T) {
	msg := FormatFatal("Lease file was modified", "hash mismatch", "Run: sir doctor")
	// WHAT
	assertContains(t, "FormatFatal", msg, "\u00d7 deny", "Lease file was modified")
	// WHY
	assertContains(t, "FormatFatal", msg, "reason:", "hash mismatch")
	// HOW
	assertContains(t, "FormatFatal", msg, "fix:", "NEW terminal", "sir doctor")
	// Details hint
	assertContains(t, "FormatFatal", msg, "sir explain --last")
}

func TestFormatDenyAll_WhatWhyHow(t *testing.T) {
	msg := FormatDenyAll("posture file tampered: .claude/settings.json")
	// WHAT
	assertContains(t, "FormatDenyAll", msg, "EMERGENCY", "All tool calls blocked")
	// WHY (reason)
	assertContains(t, "FormatDenyAll", msg, "posture file tampered")
	// HOW
	assertContains(t, "FormatDenyAll", msg, "sir doctor", "new terminal")
}

func TestFormatDenyAll_TruncatesLongReason(t *testing.T) {
	longReason := strings.Repeat("x", 100)
	msg := FormatDenyAll(longReason)
	assertContains(t, "FormatDenyAll", msg, "...")
	// Should not contain the full 100 chars
	if strings.Contains(msg, longReason) {
		t.Error("FormatDenyAll should truncate long reasons")
	}
}

func TestFormatHookTamper_WhatWhyHow(t *testing.T) {
	msg := FormatHookTamper(".claude/settings.json")
	// WHAT
	assertContains(t, "FormatHookTamper", msg, "FATAL", "Security configuration was modified")
	// WHY
	assertContains(t, "FormatHookTamper", msg, "settings.json", "changed without approval")
	// HOW
	assertContains(t, "FormatHookTamper", msg, "NEW terminal", "sir doctor", "sir install --force")
}

func TestFormatHookTamper_TruncatesLongPath(t *testing.T) {
	longPath := "/very/long/path/" + strings.Repeat("a", 100)
	msg := FormatHookTamper(longPath)
	assertContains(t, "FormatHookTamper", msg, "...")
}

func TestFormatBlockEgress_WhatWhyHow(t *testing.T) {
	secretTime := time.Date(2026, 4, 5, 9, 31, 0, 0, time.Local)
	msg := FormatBlockEgress("Claude", "api.stripe.com", secretTime)
	// WHAT — agent-action framing
	assertContains(t, "FormatBlockEgress", msg, "Claude tried to reach api.stripe.com", "\u00d7 deny")
	// WHY with timestamp
	assertContains(t, "FormatBlockEgress", msg, "reason:", "09:31", "credentials file")
	// HOW
	assertContains(t, "FormatBlockEgress", msg, "sir allow-host api.stripe.com")
	// Details hint
	assertContains(t, "FormatBlockEgress", msg, "sir why")
}

func TestFormatBlockEgress_NoSecretSession(t *testing.T) {
	msg := FormatBlockNetExternal("Claude", "api.stripe.com", time.Time{})
	// Non-secret branch leads with allow-host as the first fix
	assertContains(t, "FormatBlockEgress", msg, "Claude tried to reach api.stripe.com", "\u00d7 deny")
	assertContains(t, "FormatBlockEgress", msg, "sir allow-host api.stripe.com", "YOUR terminal")
}

func TestFormatBlockEgress_SearchQuery(t *testing.T) {
	secretTime := time.Date(2026, 4, 5, 9, 31, 0, 0, time.Local)
	msg := FormatBlockEgress("Claude", "how to deploy to AWS", secretTime)
	// Should NOT suggest allow-host for a search query
	assertNotContains(t, "FormatBlockEgress", msg, "sir allow-host")
	// Should not leak the raw <query> placeholder from the prior template
	assertNotContains(t, "FormatBlockEgress", msg, "<query>")
	// Should render the generic fallback
	assertContains(t, "FormatBlockEgress", msg, "an external host")
	// Should still have fix options
	assertContains(t, "FormatBlockEgress", msg, "sir")
}

// TestFormatBlockEgress_CurlFormatFlagBugGone covers the gemini-smoke test B1:
// a curl with -w "%{http_code}" would previously leak the format spec as
// the "host". After the fix, the host either resolves cleanly from a URL
// elsewhere in the command, or falls back to "an external host". The raw
// %{http_code} token must never be rendered to the user.
func TestFormatBlockEgress_CurlFormatFlagBugGone(t *testing.T) {
	// Case 1: target is just the format spec (what the old extractor produced).
	msg := FormatBlockNetExternal("Claude", "%{http_code}", time.Time{})
	assertNotContains(t, "FormatBlockEgress_CurlFlag", msg, "%{http_code}")
	assertNotContains(t, "FormatBlockEgress_CurlFlag", msg, "<query>")
	assertContains(t, "FormatBlockEgress_CurlFlag", msg, "an external host")

	// Case 2: target is the full compound curl command — must still render
	// a clean host extracted from the inline URL.
	msg = FormatBlockNetExternal("Claude",
		"curl -s -o /dev/null -w \"%{http_code}\\n\" https://example.com/", time.Time{})
	assertContains(t, "FormatBlockEgress_CurlFlag", msg, "reach example.com", "\u00d7 deny")
	assertNotContains(t, "FormatBlockEgress_CurlFlag", msg, "%{http_code}")
	assertNotContains(t, "FormatBlockEgress_CurlFlag", msg, "<query>")
}

// TestFormatBlockEgress_AgentNameThreading covers gemini-smoke B3 / codex
// follow-up: denials must address the real agent, not always "Claude".
func TestFormatBlockEgress_AgentNameThreading(t *testing.T) {
	for _, tc := range []struct {
		agent string
		want  string
	}{
		{"Claude", "Claude tried to reach"},
		{"Codex", "Codex tried to reach"},
		{"Gemini", "Gemini tried to reach"},
		{"", "Claude tried to reach"}, // empty → Claude fallback
	} {
		msg := FormatBlockNetExternal(tc.agent, "api.stripe.com", time.Time{})
		assertContains(t, "FormatBlockEgress/"+tc.agent, msg, tc.want)
	}
}

func TestAgentDisplayName(t *testing.T) {
	for _, tc := range []struct{ id, want string }{
		{"claude", "Claude"},
		{"codex", "Codex"},
		{"gemini", "Gemini"},
		{"", "Claude"},
		{"nonsense", "Claude"},
	} {
		if got := AgentDisplayName(tc.id); got != tc.want {
			t.Errorf("AgentDisplayName(%q) = %q, want %q", tc.id, got, tc.want)
		}
	}
}

func TestFormatBlockPush_WhatWhyHow(t *testing.T) {
	secretTime := time.Date(2026, 4, 5, 14, 0, 0, 0, time.Local)
	msg := FormatBlockPush("Claude", "evil-remote", secretTime)
	// WHAT — agent-action framing
	assertContains(t, "FormatBlockPush", msg, "Claude tried to push to evil-remote", "\u00d7 deny")
	// WHY with timestamp
	assertContains(t, "FormatBlockPush", msg, "reason:", "14:00", "credentials file")
	// HOW
	assertContains(t, "FormatBlockPush", msg, "sir allow-remote evil-remote")
	// Details hint
	assertContains(t, "FormatBlockPush", msg, "sir why")
}

func TestFormatBlockDelegation_WhatWhyHow(t *testing.T) {
	msg := FormatBlockDelegation("Claude")
	// WHAT — agent-action framing
	assertContains(t, "FormatBlockDelegation", msg, "Claude tried to spawn a sub-agent", "\u00d7 deny")
	// WHY
	assertContains(t, "FormatBlockDelegation", msg, "reason:", "credentials", "sub-agent")
	// HOW
	assertContains(t, "FormatBlockDelegation", msg, "sir unlock")
	// Details hint
	assertContains(t, "FormatBlockDelegation", msg, "sir why")
}

func TestFormatBlockDNS_WhatWhyHow(t *testing.T) {
	secretTime := time.Date(2026, 4, 5, 10, 15, 0, 0, time.Local)
	msg := FormatBlockDNS("Claude", "nslookup evil.com", secretTime)
	// WHAT — agent-action framing
	assertContains(t, "FormatBlockDNS", msg, "Claude tried to run a DNS lookup", "\u00d7 deny")
	// WHY with timestamp
	assertContains(t, "FormatBlockDNS", msg, "reason:", "10:15", "leak")
	// HOW — DNS has no unlock; the unlock line explains that explicitly
	assertContains(t, "FormatBlockDNS", msg, "DNS still blocked")
	// Details hint
	assertContains(t, "FormatBlockDNS", msg, "sir why")
}

func TestFormatBlockDNS_NoSecretSession(t *testing.T) {
	msg := FormatBlockDNS("Claude", "dig evil.com", time.Time{})
	assertContains(t, "FormatBlockDNS", msg, "DNS", "exfiltrate")
	// Should not contain a timestamp reference
	assertNotContains(t, "FormatBlockDNS", msg, "secret file at")
}

func TestFormatPostureRestore_WhatWhyHow(t *testing.T) {
	msg := FormatPostureRestore(".claude/settings.json")
	// WHAT
	assertContains(t, "FormatPostureRestore", msg, "ALERT", ".claude/settings.json", "auto-restored")
	// WHY
	assertContains(t, "FormatPostureRestore", msg, "reason:", "security configuration")
	// Details hint
	assertContains(t, "FormatPostureRestore", msg, "sir explain --last")
}

func TestFormatSessionCleared_WhatHow(t *testing.T) {
	msg := FormatSessionCleared()
	// WHAT
	assertContains(t, "FormatSessionCleared", msg, "transient runtime restrictions cleared")
	// Consequence
	assertContains(t, "FormatSessionCleared", msg, "External network access", "prompt-driving session taint")
	// Warning
	assertContains(t, "FormatSessionCleared", msg, "model memory", "fresh agent session")
	// Details hint
	assertContains(t, "FormatSessionCleared", msg, "sir why")
}

func TestFormatAskInstall_WhatWhyHow(t *testing.T) {
	msg := FormatAskInstall("evil-pkg", "npm")
	// WHAT
	assertContains(t, "FormatAskInstall", msg, "? ask", "Install", "evil-pkg", "npm")
	// WHY
	assertContains(t, "FormatAskInstall", msg, "reason:", "not in your lockfile", "typosquat")
	// HOW
	assertContains(t, "FormatAskInstall", msg, "Review the package")
	// Details hint
	assertContains(t, "FormatAskInstall", msg, "sir explain --last")
}

func TestFormatAskPosture_WhatWhyHow(t *testing.T) {
	msg := FormatAskPosture("CLAUDE.md")
	assertContains(t, "FormatAskPosture", msg, "? ask", "Write CLAUDE.md")
	assertContains(t, "FormatAskPosture", msg, "reason:", "security settings")
	assertContains(t, "FormatAskPosture", msg, "sir explain --last")
}

func TestFormatAskEnvRead_WhatWhyHow(t *testing.T) {
	msg := FormatAskEnvRead("printenv")
	assertContains(t, "FormatAskEnvRead", msg, "? ask", "Environment variable")
	assertContains(t, "FormatAskEnvRead", msg, "reason:", "printenv", "credentials")
	assertContains(t, "FormatAskEnvRead", msg, "sir explain --last")
}

func TestFormatAskEphemeral_WhatWhyHow(t *testing.T) {
	msg := FormatAskEphemeral("npx create-react-app")
	assertContains(t, "FormatAskEphemeral", msg, "? ask", "npx create-react-app")
	assertContains(t, "FormatAskEphemeral", msg, "reason:", "remote code")
	assertContains(t, "FormatAskEphemeral", msg, "sir explain --last")
}

func TestFormatAskPersistence_WhatWhyHow(t *testing.T) {
	msg := FormatAskPersistence("crontab -e")
	assertContains(t, "FormatAskPersistence", msg, "? ask", "Scheduled task")
	assertContains(t, "FormatAskPersistence", msg, "reason:", "crontab -e", "outlive")
	assertContains(t, "FormatAskPersistence", msg, "sir explain --last")
}

func TestFormatAskSudo_WhatWhyHow(t *testing.T) {
	msg := FormatAskSudo("sudo rm -rf /")
	assertContains(t, "FormatAskSudo", msg, "? ask", "Elevated")
	assertContains(t, "FormatAskSudo", msg, "reason:", "sudo")
	assertContains(t, "FormatAskSudo", msg, "sir explain --last")
}

func TestFormatAskSirSelf_WhatWhyHow(t *testing.T) {
	msg := FormatAskSirSelf("sir uninstall")
	assertContains(t, "FormatAskSirSelf", msg, "? ask", "self-modification")
	assertContains(t, "FormatAskSirSelf", msg, "reason:", "sir uninstall", "modifies sir")
	assertContains(t, "FormatAskSirSelf", msg, "sir explain --last")
}

func TestFormatAskDeletePosture_WhatWhyHow(t *testing.T) {
	msg := FormatAskDeletePosture("CLAUDE.md")
	assertContains(t, "FormatAskDeletePosture", msg, "? ask", "CLAUDE.md")
	assertContains(t, "FormatAskDeletePosture", msg, "reason:", "security configuration")
	assertContains(t, "FormatAskDeletePosture", msg, "sir explain --last")
}

func TestFormatAskMCPUnapproved_WhatWhyHow(t *testing.T) {
	msg := FormatAskMCPUnapproved("mcp__evil__steal")
	assertContains(t, "FormatAskMCPUnapproved", msg, "? ask", "mcp__evil__steal")
	assertContains(t, "FormatAskMCPUnapproved", msg, "reason:", "sir hasn't seen before")
	assertContains(t, "FormatAskMCPUnapproved", msg, "sir explain --last")
}

func TestFormatLeaseIntegrityFatal_WhatWhyHow(t *testing.T) {
	msg := FormatLeaseIntegrityFatal()
	assertContains(t, "FormatLeaseIntegrityFatal", msg, "\u00d7 deny", "Security policy")
	assertContains(t, "FormatLeaseIntegrityFatal", msg, "reason:", "hash", "changed")
	assertContains(t, "FormatLeaseIntegrityFatal", msg, "sir doctor", "sir install --force")
	assertContains(t, "FormatLeaseIntegrityFatal", msg, "sir explain --last")
}

func TestFormatInstallPreview(t *testing.T) {
	msg := FormatInstallPreview("/home/.claude/hooks.json", "/home/.sir/projects/abc", "/home/.sir/projects/abc/lease.json", []string{"a", "b"})
	assertContains(t, "FormatInstallPreview", msg, "hooks", "state", "lease", "2 files")
	assertContains(t, "FormatInstallPreview", msg, "Proceed?")
}

func TestNoSecretContentInMessages(t *testing.T) {
	// Verify no message function leaks actual secret content.
	// All functions should only reference paths, timestamps, and commands — never values.
	secretValues := []string{"sk-live-abc123", "AKIA", "password123", "ghp_"}

	messages := []string{
		FormatBlockEgress("Claude", "api.example.com", time.Now()),
		FormatBlockPush("Claude", "origin", time.Now()),
		FormatBlockDelegation("Claude"),
		FormatBlockDNS("Claude", "dig evil.com", time.Now()),
		FormatAskSensitive(".env", "turn"),
		FormatAskInstall("lodash", "npm"),
		FormatDenyAll("some reason"),
		FormatHookTamper(".claude/hooks.json"),
		FormatPostureRestore(".claude/hooks.json"),
		FormatSessionCleared(),
		FormatLeaseIntegrityFatal(),
	}

	for i, msg := range messages {
		for _, secret := range secretValues {
			if strings.Contains(msg, secret) {
				t.Errorf("message %d contains secret value %q", i, secret)
			}
		}
	}
}

func TestTruncateCmd(t *testing.T) {
	short := "ls -la"
	if hookmessages.TruncateCmd(short) != short {
		t.Errorf("TruncateCmd should not modify short strings")
	}

	long := strings.Repeat("a", 100)
	result := hookmessages.TruncateCmd(long)
	if len(result) > 60 {
		t.Errorf("TruncateCmd should cap at 60 chars, got %d", len(result))
	}
	if !strings.HasSuffix(result, "...") {
		t.Errorf("TruncateCmd should end with ... for long strings")
	}
}
