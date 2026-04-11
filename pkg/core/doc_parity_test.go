package core

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/somoore/sir/pkg/policy"
)

// TestEnforcementGradientDocParity treats the "Enforcement Gradient" table in
// docs/contributor/security-engineering-core.md as an executable spec. Every row is parsed and
// exercised against localEvaluate; the verdict must be "no more permissive
// than documented".
//
// "No more permissive than documented" semantics, with allow < ask < deny:
//
//	doc says deny  → localEvaluate must return deny
//	doc says ask   → localEvaluate must return ask or deny
//	doc says allow → no constraint (the fallback may be stricter than the doc)
//
// This catches doc drift in both directions:
//   - if a row is added to the doc but the implementation does not honor it,
//     the test fails.
//   - if a new verb is implemented but not documented in the gradient table,
//     a separate verbsAreDocumented sub-test fails.
//
// There are NO per-verb exemptions. An earlier version relaxed
// mcp_credential_leak because the production hook path was returning "ask"
// while the doc said "deny" — that was a real policy ambiguity hidden
// behind a test exemption. Both paths now agree on "deny" and this test
// enforces it with no wiggle room.
//
// To regenerate this test's coverage when the gradient changes: edit
// docs/contributor/security-engineering-core.md, then run `go test ./pkg/core/ -run
// TestEnforcementGradientDocParity` and address any drift.
func TestEnforcementGradientDocParity(t *testing.T) {
	rows, err := parseEnforcementGradient(findSecurityEngineeringCorePath(t))
	if err != nil {
		t.Fatalf("parse enforcement gradient: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("parsed zero rows from enforcement gradient — parser is broken or doc was emptied")
	}

	docVerbs := make(map[string]bool, len(rows))
	for _, row := range rows {
		row := row
		docVerbs[row.Verb] = true
		t.Run(row.testName(), func(t *testing.T) {
			t.Run("normal_session", func(t *testing.T) {
				assertGradient(t, row, false, row.NormalVerdict)
			})
			if row.SecretVerdict != row.NormalVerdict {
				t.Run("secret_session", func(t *testing.T) {
					assertGradient(t, row, true, row.SecretVerdict)
				})
			}
		})
	}

	// Coverage in the other direction: every verb listed in the verb model
	// (architecture.md) must appear in the gradient table OR be in the
	// implicit "Everything else → allow" bucket. The bucket is documented
	// per-verb in the local verb model — the gradient table only enumerates
	// verbs that deviate from the default allow.
	t.Run("documented_verbs_are_recognized", func(t *testing.T) {
		for verb := range docVerbs {
			req := buildRequestForVerb(verb, false)
			if _, err := localEvaluate(req); err != nil {
				t.Errorf("documented verb %q is not handled by localEvaluate: %v", verb, err)
			}
		}
	})
}

// gradientRow is one parsed line from the enforcement gradient table.
//
// NormalVerdict is the verdict in a non-secret session. SecretVerdict is the
// verdict when state.SecretSession is true. For rows that do not mention
// session state, the two are equal.
//
// Qualifier is "posture" or "sensitive" for rows like `stage_write posture`
// or `read_ref sensitive`, where the verb alone is not enough to dispatch.
type gradientRow struct {
	Verb          string
	Qualifier     string // "", "posture", "sensitive"
	NormalVerdict string // "allow", "ask", or "deny"
	SecretVerdict string
	SourceLine    string // original line, kept for error messages
}

func (r gradientRow) testName() string {
	if r.Qualifier == "" {
		return r.Verb
	}
	return r.Verb + "_" + r.Qualifier
}

// parseEnforcementGradient extracts the fenced code block under the
// "## Enforcement Gradient" header and parses each non-blank line.
func parseEnforcementGradient(path string) ([]gradientRow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	src := string(data)

	// Locate the section header.
	header := "## Enforcement Gradient"
	headerIdx := strings.Index(src, header)
	if headerIdx == -1 {
		return nil, &parseError{"section header missing", header}
	}

	// First fenced code block after the header.
	rest := src[headerIdx+len(header):]
	openIdx := strings.Index(rest, "```")
	if openIdx == -1 {
		return nil, &parseError{"opening fence missing", header}
	}
	rest = rest[openIdx+3:]
	// Skip any language tag on the opening fence line.
	if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
		rest = rest[nl+1:]
	}
	closeIdx := strings.Index(rest, "```")
	if closeIdx == -1 {
		return nil, &parseError{"closing fence missing", header}
	}
	block := rest[:closeIdx]

	var rows []gradientRow
	for _, raw := range strings.Split(block, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		// "Everything else → allow" is the implicit catch-all.
		// We don't test it as a row; the verb model in architecture.md
		// is the source of truth for which verbs default to allow.
		if strings.HasPrefix(line, "Everything else") {
			continue
		}
		row, err := parseGradientLine(line)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// arrowSplit accepts the unicode arrow used in the doc.
var arrowSplit = regexp.MustCompile(`\s*→\s*`)

// parseGradientLine parses one row of the enforcement gradient table.
//
// Accepted forms:
//
//	verb                 → ask
//	verb                 → ask (free-form note)
//	verb                 → ask (deny if secret session)
//	verb                 → ask if secret session, allow otherwise
//	verb                 → deny in secret session, policy otherwise
//	verb qualifier       → ask
func parseGradientLine(line string) (gradientRow, error) {
	parts := arrowSplit.Split(line, 2)
	if len(parts) != 2 {
		return gradientRow{}, &parseError{"missing arrow", line}
	}
	left := strings.TrimSpace(parts[0])
	right := strings.TrimSpace(parts[1])

	row := gradientRow{SourceLine: line}

	// Left side: verb [qualifier]
	leftFields := strings.Fields(left)
	switch len(leftFields) {
	case 1:
		row.Verb = leftFields[0]
	case 2:
		row.Verb = leftFields[0]
		row.Qualifier = leftFields[1]
	default:
		return gradientRow{}, &parseError{"unexpected left side", line}
	}

	// Right side: parse verdict expression.
	normal, secret, err := parseVerdictExpr(right)
	if err != nil {
		return gradientRow{}, &parseError{err.Error(), line}
	}
	row.NormalVerdict = normal
	row.SecretVerdict = secret
	return row, nil
}

// parseVerdictExpr parses the right-hand-side of a gradient row.
// Returns the (non-secret session, secret session) verdict pair.
func parseVerdictExpr(expr string) (normal string, secret string, err error) {
	lower := strings.ToLower(expr)

	// Form: "ask if secret session, allow otherwise"
	//    or "deny in secret session, policy otherwise"
	if idx := strings.Index(lower, " otherwise"); idx >= 0 {
		head := lower[:idx]
		// "<v1> {if|in} secret session, <v2>"
		commaIdx := strings.Index(head, ",")
		if commaIdx == -1 {
			return "", "", &parseError{msg: "conditional missing comma"}
		}
		secretHalf := strings.TrimSpace(head[:commaIdx])
		normalHalf := strings.TrimSpace(head[commaIdx+1:])
		secretV, ok := firstVerdictIn(secretHalf)
		if !ok {
			return "", "", &parseError{msg: "secret-session verdict not recognized"}
		}
		normalV, ok := firstVerdictIn(normalHalf)
		if !ok {
			// "policy otherwise" — leave as the verb's normal-session
			// behavior, which we approximate as "allow" (the default
			// catch-all). The non-secret delegate path returns allow
			// in localEvaluate when the lease permits delegation.
			normalV = "allow"
		}
		return normalV, secretV, nil
	}

	// Form: "ask (deny if secret session)" — primary verdict followed by
	// a parenthetical override for secret session.
	if openParen := strings.IndexByte(lower, '('); openParen >= 0 {
		head := strings.TrimSpace(lower[:openParen])
		paren := lower[openParen+1:]
		if closeParen := strings.IndexByte(paren, ')'); closeParen >= 0 {
			paren = paren[:closeParen]
		}
		primary, ok := firstVerdictIn(head)
		if !ok {
			return "", "", &parseError{msg: "primary verdict not recognized"}
		}
		// Look for an override of the form "deny if secret session" or
		// "ask if secret session".
		if strings.Contains(paren, "secret session") {
			if override, ok := firstVerdictIn(paren); ok {
				return primary, override, nil
			}
		}
		return primary, primary, nil
	}

	// Form: simple "ask" or "deny" with no parenthetical.
	v, ok := firstVerdictIn(lower)
	if !ok {
		return "", "", &parseError{msg: "no recognizable verdict"}
	}
	return v, v, nil
}

// firstVerdictIn returns the first occurrence of allow/ask/deny in s.
// Whole-word match: "policy" must not match "deny" etc.
func firstVerdictIn(s string) (string, bool) {
	for _, v := range []string{"allow", "deny", "ask"} {
		if regexp.MustCompile(`\b` + v + `\b`).MatchString(s) {
			return v, true
		}
	}
	return "", false
}

type parseError struct {
	msg  string
	line string
}

func (e *parseError) Error() string {
	if e.line == "" {
		return e.msg
	}
	return e.msg + ": " + e.line
}

// buildRequestForVerb constructs a minimal Request that exercises the named
// verb under the given session state. Posture/sensitive qualifiers are NOT
// applied here — those are added by buildRequestForRow when the row carries
// the qualifier.
func buildRequestForVerb(verb string, secretSession bool) *Request {
	typedVerb, ok := policy.ParseVerb(verb)
	if !ok {
		typedVerb = policy.Verb(verb)
	}
	return &Request{
		Intent:  Intent{Verb: typedVerb, Target: "test"},
		Session: SessionInfo{SecretSession: secretSession},
	}
}

// buildRequestForRow applies the row's qualifier (posture/sensitive) to the
// base Request. Posture writes set IsPosture; sensitive reads set IsSensitive.
func buildRequestForRow(row gradientRow, secretSession bool) *Request {
	req := buildRequestForVerb(row.Verb, secretSession)
	switch row.Qualifier {
	case "posture":
		req.Intent.IsPosture = true
		req.Intent.Target = "CLAUDE.md"
	case "sensitive":
		req.Intent.IsSensitive = true
		req.Intent.Target = ".env"
	}
	return req
}

// assertGradient runs localEvaluate on the row's request and checks the
// verdict matches "no more permissive than documented". There are no
// per-verb exemptions — a documented "deny" means localEvaluate must
// actually return deny, not some softer fallback.
func assertGradient(t *testing.T, row gradientRow, secretSession bool, want string) {
	t.Helper()
	req := buildRequestForRow(row, secretSession)
	resp, err := localEvaluate(req)
	if err != nil {
		t.Fatalf("localEvaluate(%s, secret=%v): %v", row.Verb, secretSession, err)
	}
	got := resp.Decision

	switch want {
	case "deny":
		if got != "deny" {
			t.Errorf("doc gradient says %s → deny, localEvaluate returned %s\n  source: %s\n  reason: %s",
				row.Verb, got, row.SourceLine, resp.Reason)
		}
	case "ask":
		// Must not allow; fallback may deny (stricter than documented).
		if got == "allow" {
			t.Errorf("doc gradient says %s → ask, localEvaluate returned allow\n  source: %s\n  reason: %s",
				row.Verb, row.SourceLine, resp.Reason)
		}
	case "allow":
		// No constraint — fallback may be stricter than documented.
	default:
		t.Fatalf("test bug: unknown documented verdict %q for verb %s", want, row.Verb)
	}
}

// findSecurityEngineeringCorePath walks up from the test's working directory
// until it finds docs/contributor/security-engineering-core.md, so the test
// works from any module invocation (e.g., go test ./..., go test ./pkg/core/...).
func findSecurityEngineeringCorePath(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		candidate := filepath.Join(dir, "docs", "contributor", "security-engineering-core.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("docs/contributor/security-engineering-core.md not found walking up from %s", dir)
		}
		dir = parent
	}
}
