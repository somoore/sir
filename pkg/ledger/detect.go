package ledger

import "github.com/somoore/sir/pkg/detect"

// entryLocalDetection classifies an entry from the fields visible on it alone —
// alert type, verb, verdict, IFC sensitivity, and restore status. Detections
// that depend on session context (secret-session egress, repeated intent) are
// stamped by the hook evaluate path before Append and are not derived here.
func entryLocalDetection(e *Entry) (detect.Detection, bool) {
	return detect.Classify(detect.Signal{
		Verb:           e.Verb,
		Verdict:        e.Decision,
		AlertType:      e.AlertType,
		Sensitivity:    e.Sensitivity,
		TamperRestored: e.Restored,
	})
}

// stampDetection fills in a stable detection ID (and severity, when absent)
// from entry-local fields so storage stays decoupled from session state. The
// hook evaluate path stamps session-aware detections before Append; those are
// preserved here.
func stampDetection(entry *Entry) {
	if entry == nil || entry.DetectionID != "" {
		return
	}
	d, ok := entryLocalDetection(entry)
	if !ok {
		return
	}
	entry.DetectionID = string(d.ID)
	entry.DetectionRoute = d.Route.String()
	if entry.Severity == "" {
		entry.Severity = string(d.Severity)
	}
}

// DetectionID returns the stable detection ID for an entry: the stamped value
// when present, otherwise an entry-local classification so historical entries
// written before stamping still resolve a detection. Returns "" when no
// detection applies.
func DetectionID(e Entry) string {
	if e.DetectionID != "" {
		return e.DetectionID
	}
	if d, ok := entryLocalDetection(&e); ok {
		return string(d.ID)
	}
	return ""
}
