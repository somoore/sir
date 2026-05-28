package hooks

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/somoore/sir/pkg/agent"
	"github.com/somoore/sir/pkg/core"
	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
	"github.com/somoore/sir/pkg/secretview"
	"github.com/somoore/sir/pkg/session"
)

// maxInlineRedactBytes caps how much of a sensitive file the gate reads to
// build the inline redacted view.
const maxInlineRedactBytes = 1 << 20 // 1 MiB

// maxInlineRedactKeys bounds how many keys the inline view lists so the deny
// reason stays a reasonable size.
const maxInlineRedactKeys = 24

// evaluateRawSecretReadGate denies a raw read of a sensitive file when the
// active profile (team/strict) forbids it, and hands back a redacted view (key
// names with values masked) inline in the deny reason. The agent gets the
// information it needs to keep working — which keys exist — while raw values
// never enter the model context. This is a Go-side restriction: it narrows the
// oracle's ask to deny and never widens. In observe mode the deny is recorded
// as would_deny and downgraded to allow on the wire by the observe defer.
func evaluateRawSecretReadGate(payload *HookPayload, intent Intent, labels core.Label, l *lease.Lease, state *session.State, projectRoot string, ag agent.Agent) (*HookResponse, bool) {
	if l == nil || !l.DenyRawSecretReads {
		return nil, false
	}
	if intent.Verb != policy.VerbReadRef || !intent.IsSensitive {
		return nil, false
	}
	// An explicit grant (`sir approve path <secret>`) honors a rare, deliberate
	// raw read: defer to the normal ask→grant→allow path instead of denying.
	if state.HasApprovalGrant(string(policy.VerbReadRef), intent.Target) {
		return nil, false
	}

	base := filepath.Base(intent.Target)
	fix := inlineRedactedView(projectRoot, intent.Target)
	if fix == "" {
		// Fall back to pointing at the command when the file cannot be read.
		fix = "sir secret view " + intent.Target + "   (key names only, values redacted)"
	}
	fix += "\n       Need a raw value? Approve it explicitly with sir approve, or use a lower-friction profile."

	reason := FormatBlock(
		"read the secret file "+base,
		"Policy denies raw secret reads so credential values never enter the model context.",
		fix,
	)
	saveSessionBestEffort(state)
	appendEvaluationLedgerEntry(projectRoot, payload, intent, labels, policy.VerdictDeny, reason, state, l.ObserveOnly, ag)
	return &HookResponse{Decision: policy.VerdictDeny, Reason: reason}, true
}

// inlineRedactedView reads the sensitive file and renders a compact, value-free
// summary of its keys for the deny reason. Returns "" when the file cannot be
// read. It never emits a raw value — secretview.Redact masks them — so it is
// safe to surface to the model.
func inlineRedactedView(projectRoot, target string) string {
	resolved := ResolveTarget(projectRoot, target)
	f, err := os.Open(resolved) // #nosec G304 -- redacting a sensitive file the agent already named; values are masked
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, maxInlineRedactBytes)
	n, _ := f.Read(buf)
	if n == 0 {
		return ""
	}
	view := secretview.Redact(filepath.Base(resolved), buf[:n])

	var b strings.Builder
	b.WriteString("Redacted view (values masked, safe to use):\n")
	if view.Kind == "env" {
		shown := 0
		for _, e := range view.Entries {
			if shown >= maxInlineRedactKeys {
				b.WriteString(fmt.Sprintf("       ... %d more keys\n", len(view.Entries)-shown))
				break
			}
			status := "empty"
			if e.Present {
				status = fmt.Sprintf("present (%d)", e.ValueLen)
			}
			class := ""
			if e.Class != "" {
				class = " [" + e.Class + "]"
			}
			fmt.Fprintf(&b, "         %s = %s%s\n", e.Key, status, class)
			shown++
		}
	} else {
		fmt.Fprintf(&b, "         opaque file: %d bytes, %d credential-like pattern(s)\n", view.Bytes, view.CredentialHits)
	}
	return strings.TrimRight(b.String(), "\n")
}
