package main

import (
	"fmt"
	"html"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
	"github.com/somoore/sir/pkg/session"
)

func renderTraceHTML(entries []ledger.Entry, sess *session.State) string {
	counts := traceDecisionCounts(entries)

	var b strings.Builder
	b.WriteString(traceHTMLHeader)
	b.WriteString(traceSessionMetadata(sess))
	b.WriteString(traceSummaryBar(counts, len(entries)))
	b.WriteString(traceTimeline(entries))
	b.WriteString(traceHTMLFooter)
	return b.String()
}

func traceDecisionCounts(entries []ledger.Entry) map[string]int {
	counts := map[string]int{"allow": 0, "ask": 0, "deny": 0, "alert": 0}
	for _, e := range entries {
		switch e.Decision {
		case "allow":
			counts["allow"]++
		case "ask":
			counts["ask"]++
		case "deny":
			counts["deny"]++
		default:
			counts["alert"]++
		}
		if e.AlertType != "" {
			counts["alert"]++
		}
	}
	return counts
}

func traceSessionMetadata(sess *session.State) string {
	var b strings.Builder
	b.WriteString(`<div class="session-meta">`)
	if sess != nil {
		b.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">Session</span><span class="meta-value">%s</span></div>`, html.EscapeString(sess.SessionID)))
		b.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">Started</span><span class="meta-value">%s</span></div>`, sess.StartedAt.Format("2006-01-02 15:04:05")))
		posture := sess.Posture
		if posture == "" {
			posture = "normal"
		}
		b.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">Posture</span><span class="meta-value posture-%s">%s</span></div>`, html.EscapeString(string(posture)), html.EscapeString(string(posture))))
		secretStatus := "clean"
		if sess.SecretSession {
			secretStatus = "tainted"
		}
		secretClass := "secret-clean"
		if sess.SecretSession {
			secretClass = "secret-tainted"
		}
		b.WriteString(fmt.Sprintf(`<div class="meta-item"><span class="meta-label">Secrets</span><span class="meta-value %s">%s</span></div>`, secretClass, html.EscapeString(secretStatus)))
		if sess.DenyAll {
			b.WriteString(`<div class="meta-item"><span class="meta-label">Mode</span><span class="meta-value deny-all">DENY-ALL</span></div>`)
		}
	} else {
		b.WriteString(`<div class="meta-item"><span class="meta-label">Session</span><span class="meta-value">no active session</span></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func traceSummaryBar(counts map[string]int, total int) string {
	var b strings.Builder
	b.WriteString(`<div class="summary-bar">`)
	b.WriteString(fmt.Sprintf(`<span class="summary-allow">%d allowed</span>`, counts["allow"]))
	b.WriteString(fmt.Sprintf(`<span class="summary-ask">%d asked</span>`, counts["ask"]))
	b.WriteString(fmt.Sprintf(`<span class="summary-deny">%d blocked</span>`, counts["deny"]))
	b.WriteString(fmt.Sprintf(`<span class="summary-alert">%d alerts</span>`, counts["alert"]))
	b.WriteString(fmt.Sprintf(`<span class="summary-total">%d total</span>`, total))
	b.WriteString(`</div>`)
	return b.String()
}

func traceTimeline(entries []ledger.Entry) string {
	var b strings.Builder
	b.WriteString(`<div class="timeline">`)
	for _, e := range entries {
		decisionClass := e.Decision
		if e.AlertType != "" {
			decisionClass = "alert"
		}

		icon := traceDecisionIcon(e.Decision, e.AlertType)
		reason := html.EscapeString(e.Reason)
		if len(reason) > 120 {
			reason = reason[:120] + "..."
		}
		target := html.EscapeString(e.Target)
		if len(target) > 80 {
			target = "..." + target[len(target)-77:]
		}

		b.WriteString(fmt.Sprintf(`<div class="entry %s">`, html.EscapeString(decisionClass)))
		b.WriteString(fmt.Sprintf(`<div class="entry-icon">%s</div>`, icon))
		b.WriteString(`<div class="entry-body">`)
		b.WriteString(fmt.Sprintf(`<div class="entry-header"><span class="entry-time">%s</span><span class="entry-index">#%d</span><span class="entry-decision %s">%s</span></div>`,
			e.Timestamp.Format("15:04:05"), e.Index, html.EscapeString(e.Decision), html.EscapeString(strings.ToUpper(e.Decision))))
		b.WriteString(fmt.Sprintf(`<div class="entry-detail"><span class="entry-tool">%s</span><span class="entry-verb">%s</span></div>`,
			html.EscapeString(e.ToolName), html.EscapeString(e.Verb)))
		b.WriteString(fmt.Sprintf(`<div class="entry-target">%s</div>`, target))
		if reason != "" {
			b.WriteString(fmt.Sprintf(`<div class="entry-reason">%s</div>`, reason))
		}
		if e.AlertType != "" {
			b.WriteString(fmt.Sprintf(`<div class="entry-alert-type">%s</div>`, html.EscapeString(e.AlertType)))
		}
		if e.Sensitivity != "" {
			b.WriteString(fmt.Sprintf(`<div class="entry-label label-sensitivity">sensitivity: %s</div>`, html.EscapeString(e.Sensitivity)))
		}
		b.WriteString(`</div></div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

func traceDecisionIcon(decision, alertType string) string {
	if alertType != "" {
		return `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1L1 14h14L8 1z" fill="#f97316" stroke="#f97316"/><path d="M8 6v4M8 11.5v.5" stroke="#1a1a2e" stroke-width="1.5" stroke-linecap="round"/></svg>`
	}
	switch decision {
	case "allow":
		return `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill="#22c55e"/><path d="M5 8l2 2 4-4" stroke="#1a1a2e" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>`
	case "ask":
		return `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill="#eab308"/><path d="M8 5v4M8 11v.5" stroke="#1a1a2e" stroke-width="1.5" stroke-linecap="round"/></svg>`
	case "deny":
		return `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill="#ef4444"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5" stroke="#1a1a2e" stroke-width="1.5" stroke-linecap="round"/></svg>`
	default:
		return `<svg width="16" height="16" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" fill="#6b7280"/></svg>`
	}
}

const traceHTMLHeader = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>sir trace — session timeline</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: "SF Mono", "Menlo", "Consolas", monospace;
    background: #0d0d1a;
    color: #c9c9d9;
    line-height: 1.5;
    padding: 2rem;
    max-width: 900px;
    margin: 0 auto;
  }
  h1 {
    font-size: 1.1rem;
    font-weight: 600;
    color: #e0e0f0;
    margin-bottom: 1.5rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
  }
  .session-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 1.5rem;
    padding: 1rem 1.25rem;
    background: #13132a;
    border: 1px solid #252545;
    border-radius: 6px;
    margin-bottom: 1rem;
  }
  .meta-item { display: flex; flex-direction: column; gap: 0.15rem; }
  .meta-label { font-size: 0.65rem; color: #6b6b8a; text-transform: uppercase; letter-spacing: 0.08em; }
  .meta-value { font-size: 0.8rem; color: #a0a0c0; }
  .posture-normal { color: #22c55e; }
  .posture-elevated { color: #eab308; }
  .posture-critical { color: #ef4444; }
  .secret-clean { color: #22c55e; }
  .secret-tainted { color: #ef4444; font-weight: 600; }
  .deny-all { color: #ef4444; font-weight: 700; text-transform: uppercase; }
  .summary-bar {
    display: flex;
    gap: 1.25rem;
    padding: 0.75rem 1.25rem;
    background: #13132a;
    border: 1px solid #252545;
    border-radius: 6px;
    margin-bottom: 2rem;
    font-size: 0.8rem;
  }
  .summary-allow { color: #22c55e; }
  .summary-ask { color: #eab308; }
  .summary-deny { color: #ef4444; }
  .summary-alert { color: #f97316; }
  .summary-total { color: #6b6b8a; margin-left: auto; }
  .timeline {
    position: relative;
    padding-left: 2rem;
  }
  .timeline::before {
    content: "";
    position: absolute;
    left: 7px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: #252545;
  }
  .entry {
    display: flex;
    gap: 1rem;
    padding: 0.75rem 0;
    position: relative;
    border-bottom: 1px solid #1a1a30;
  }
  .entry:last-child { border-bottom: none; }
  .entry-icon {
    flex-shrink: 0;
    width: 16px;
    height: 16px;
    margin-top: 0.15rem;
    position: relative;
    z-index: 1;
    margin-left: -2rem;
  }
  .entry-body { flex: 1; min-width: 0; }
  .entry-header {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin-bottom: 0.25rem;
  }
  .entry-time { font-size: 0.7rem; color: #6b6b8a; }
  .entry-index { font-size: 0.7rem; color: #4a4a6a; }
  .entry-decision {
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
  }
  .entry-decision.allow { background: #22c55e20; color: #22c55e; }
  .entry-decision.ask { background: #eab30820; color: #eab308; }
  .entry-decision.deny { background: #ef444420; color: #ef4444; }
  .entry-detail {
    display: flex;
    gap: 0.5rem;
    font-size: 0.75rem;
    margin-bottom: 0.2rem;
  }
  .entry-tool { color: #8888b0; }
  .entry-verb { color: #a78bfa; }
  .entry-target {
    font-size: 0.75rem;
    color: #7a7a9a;
    word-break: break-all;
  }
  .entry-reason {
    font-size: 0.7rem;
    color: #5a5a7a;
    margin-top: 0.15rem;
    font-style: italic;
  }
  .entry-alert-type {
    display: inline-block;
    font-size: 0.65rem;
    font-weight: 600;
    color: #f97316;
    background: #f9731620;
    padding: 0.1rem 0.4rem;
    border-radius: 3px;
    margin-top: 0.25rem;
  }
  .entry-label {
    display: inline-block;
    font-size: 0.6rem;
    padding: 0.05rem 0.35rem;
    border-radius: 3px;
    margin-top: 0.2rem;
  }
  .label-sensitivity {
    background: #ef444415;
    color: #ef4444;
    border: 1px solid #ef444430;
  }
  .entry.alert { border-left: 2px solid #f97316; padding-left: 0.5rem; }
  .entry.deny { border-left: 2px solid #ef4444; padding-left: 0.5rem; }
</style>
</head>
<body>
<h1>sir trace</h1>
`

const traceHTMLFooter = `
</body>
</html>
`
