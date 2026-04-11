package telemetry

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strings"

	"github.com/somoore/sir/pkg/ledger"
)

func sanitizeLogEvent(ev LogEvent) LogEvent {
	ev.Reason = ledger.RedactString(ev.Reason)
	ev.Evidence = ledger.RedactEvidence(ev.Evidence)
	ev.DiffSummary = ledger.RedactString(ev.DiffSummary)
	return ev
}

// RedactTarget returns a privacy-preserving form of a target path or URL
// suitable for telemetry. Secret-labeled targets are reduced to a sha256
// hash prefix; network verbs are reduced to hostname only; everything else
// is returned unchanged. The redaction rules ensure no secret content,
// query strings, or full filesystem paths leave the host.
func RedactTarget(target, sensitivity, verb string) string {
	if target == "" {
		return ""
	}
	if sensitivity == "secret" {
		sum := sha256.Sum256([]byte(target))
		return "sha256:" + hex.EncodeToString(sum[:])
	}
	switch verb {
	case "net_external", "net_allowlisted", "net_local", "dns_lookup", "push_origin", "push_remote":
		if host := hostnameOnly(target); host != "" {
			return host
		}
	}
	return target
}

func hostnameOnly(target string) string {
	if parsed, err := url.Parse(target); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	s := target
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// severityFromEvent maps a sir verdict + alert severity to OTLP severity
// number and text. The mapping intentionally compresses sir's verdict space
// onto the OTLP severity ladder so collectors can filter by standard fields:
//
//	HIGH alert      -> 17 ERROR
//	MEDIUM | deny   -> 13 WARN
//	ask             ->  9 INFO
//	allow / other   ->  5 DEBUG
func severityFromEvent(ev LogEvent) (int, string) {
	if strings.EqualFold(ev.Severity, "HIGH") {
		return 17, "ERROR"
	}
	if strings.EqualFold(ev.Severity, "MEDIUM") || strings.EqualFold(ev.Verdict, "deny") {
		return 13, "WARN"
	}
	if strings.EqualFold(ev.Verdict, "ask") {
		return 9, "INFO"
	}
	return 5, "DEBUG"
}
