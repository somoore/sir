package session

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"time"
)

// LineageLabel is the session-local representation of a label propagated from
// evidence to a derived file path.
type LineageLabel struct {
	Sensitivity string `json:"sensitivity"`
	Trust       string `json:"trust"`
	Provenance  string `json:"provenance"`
}

// LineageEvidence records a visible boundary event that can taint later file
// writes within the same turn.
type LineageEvidence struct {
	ID         string         `json:"id"`
	SourceKind string         `json:"source_kind"`
	SourceRef  string         `json:"source_ref"`
	Turn       int            `json:"turn"`
	Confidence string         `json:"confidence"`
	Labels     []LineageLabel `json:"labels"`
	RecordedAt time.Time      `json:"recorded_at"`
}

// DerivedPathRecord is the persistent lineage attached to a file path.
type DerivedPathRecord struct {
	EvidenceIDs []string       `json:"evidence_ids,omitempty"`
	Labels      []LineageLabel `json:"labels,omitempty"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// RecordLineageEvidence appends a same-turn evidence record unless an
// equivalent record already exists for the current turn.
func (s *State) RecordLineageEvidence(sourceKind, sourceRef, confidence string, labels []LineageLabel) {
	if len(labels) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureLineageLocked()
	normalized := normalizeLineageLabels(labels)
	for _, evidence := range s.ActiveEvidence {
		if evidence.SourceKind == sourceKind && evidence.SourceRef == sourceRef && evidence.Turn == s.TurnCounter && sameLineageLabels(evidence.Labels, normalized) {
			return
		}
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d|%d", sourceKind, sourceRef, s.TurnCounter, len(s.ActiveEvidence))))
	s.ActiveEvidence = append(s.ActiveEvidence, LineageEvidence{
		ID:         fmt.Sprintf("%x", sum[:8]),
		SourceKind: sourceKind,
		SourceRef:  sourceRef,
		Turn:       s.TurnCounter,
		Confidence: confidence,
		Labels:     normalized,
		RecordedAt: time.Now(),
	})
}

// AttachActiveEvidenceToPath persists the current turn's evidence set onto a
// canonical file path.
func (s *State) AttachActiveEvidenceToPath(path string) {
	if path == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ActiveEvidence) == 0 {
		return
	}
	s.ensureLineageLocked()
	record := s.DerivedFileLineage[path]
	for _, evidence := range s.ActiveEvidence {
		record.EvidenceIDs = appendIfMissing(record.EvidenceIDs, evidence.ID)
		record.Labels = mergeLineageLabels(record.Labels, evidence.Labels)
	}
	record.UpdatedAt = time.Now()
	s.DerivedFileLineage[path] = record
}

// DerivedLabelsForPath returns a copy of the labels attached to a derived path.
func (s *State) DerivedLabelsForPath(path string) []LineageLabel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DerivedFileLineage == nil {
		return nil
	}
	record, ok := s.DerivedFileLineage[path]
	if !ok {
		return nil
	}
	return append([]LineageLabel(nil), record.Labels...)
}

// DerivedLabelsForPaths merges labels across multiple derived paths.
func (s *State) DerivedLabelsForPaths(paths []string) []LineageLabel {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.DerivedFileLineage == nil {
		return nil
	}
	var out []LineageLabel
	for _, path := range paths {
		if record, ok := s.DerivedFileLineage[path]; ok {
			out = mergeLineageLabels(out, record.Labels)
		}
	}
	return out
}

// DerivedPaths returns the tracked canonical file paths with persistent lineage.
func (s *State) DerivedPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.DerivedFileLineage) == 0 {
		return nil
	}
	out := make([]string, 0, len(s.DerivedFileLineage))
	for path := range s.DerivedFileLineage {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func (s *State) ensureLineageLocked() {
	if s.DerivedFileLineage == nil {
		s.DerivedFileLineage = make(map[string]DerivedPathRecord)
	}
}

func (s *State) clearTurnEvidenceLocked() {
	s.ActiveEvidence = nil
}

func normalizeLineageLabels(labels []LineageLabel) []LineageLabel {
	out := append([]LineageLabel(nil), labels...)
	sort.Slice(out, func(i, j int) bool {
		a := out[i]
		b := out[j]
		if a.Sensitivity != b.Sensitivity {
			return a.Sensitivity < b.Sensitivity
		}
		if a.Trust != b.Trust {
			return a.Trust < b.Trust
		}
		return a.Provenance < b.Provenance
	})
	return dedupeLineageLabels(out)
}

func mergeLineageLabels(dst, src []LineageLabel) []LineageLabel {
	return dedupeLineageLabels(append(append([]LineageLabel(nil), dst...), src...))
}

func dedupeLineageLabels(labels []LineageLabel) []LineageLabel {
	seen := map[LineageLabel]struct{}{}
	out := make([]LineageLabel, 0, len(labels))
	for _, label := range labels {
		if _, ok := seen[label]; ok {
			continue
		}
		seen[label] = struct{}{}
		out = append(out, label)
	}
	sort.Slice(out, func(i, j int) bool {
		a := out[i]
		b := out[j]
		if a.Sensitivity != b.Sensitivity {
			return a.Sensitivity < b.Sensitivity
		}
		if a.Trust != b.Trust {
			return a.Trust < b.Trust
		}
		return a.Provenance < b.Provenance
	})
	return out
}

func sameLineageLabels(a, b []LineageLabel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appendIfMissing(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
