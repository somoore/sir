package ledger

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// RedactPreview returns a redacted preview for secret-labeled content.
func RedactPreview(content string, isSecret bool) string {
	if isSecret {
		return "[REDACTED - secret-labeled content]"
	}
	if len(content) > 80 {
		return content[:80] + "..."
	}
	return content
}

// computeHash computes the SHA-256 hash of an entry using length-prefixed
// field encoding. Length prefixing prevents delimiter injection attacks where
// two different field combinations could otherwise produce the same hash via
// a delimiter character embedded in one field colliding with the boundary in
// another.
func computeHash(e *Entry) string {
	switch v := hashVersionForEntry(e); {
	case v <= legacyHashVersion:
		return computeHashV1(e)
	case v == 2:
		return computeHashV2(e)
	case v == 3:
		return computeHashV3(e)
	default:
		return computeHashV4(e)
	}
}

func computeHashV1(e *Entry) string {
	h := sha256.New()
	writeField := func(value string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		h.Write(lenBuf[:])     //nolint:errcheck
		h.Write([]byte(value)) //nolint:errcheck
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:]) //nolint:errcheck
	writeField(e.Timestamp.Format(time.RFC3339Nano))
	writeField(e.ToolName)
	writeField(e.Verb)
	writeField(e.Target)
	writeField(e.Sensitivity)
	writeField(e.Trust)
	writeField(e.Provenance)
	writeField(e.Decision)
	writeField(e.Reason)
	writeField(e.ContentHash)
	writeField(e.Preview)
	writeField(e.Severity)
	writeField(e.AlertType)
	return hex.EncodeToString(h.Sum(nil))
}

func computeHashV2(e *Entry) string {
	h := sha256.New()
	writeField := func(value string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		h.Write(lenBuf[:])     //nolint:errcheck
		h.Write([]byte(value)) //nolint:errcheck
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:]) //nolint:errcheck
	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], uint64(hashVersionForEntry(e)))
	h.Write(versionBuf[:]) //nolint:errcheck
	writeField(e.Timestamp.Format(time.RFC3339Nano))
	writeField(e.ToolName)
	writeField(e.Verb)
	writeField(e.Target)
	writeField(e.Sensitivity)
	writeField(e.Trust)
	writeField(e.Provenance)
	writeField(e.Decision)
	writeField(e.Reason)
	writeField(e.ContentHash)
	writeField(e.Preview)
	writeField(e.Severity)
	writeField(e.AlertType)
	writeField(e.Evidence)
	writeField(e.Agent)
	writeField(e.DiffSummary)
	if e.Restored {
		writeField("true")
	} else {
		writeField("false")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// computeHashV3 extends V2 with the stable detection ID so that derived
// detection metadata is tamper-evident in the chain. V2 entries are left
// untouched and still verify under computeHashV2.
func computeHashV3(e *Entry) string {
	h := sha256.New()
	writeField := func(value string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		h.Write(lenBuf[:])     //nolint:errcheck
		h.Write([]byte(value)) //nolint:errcheck
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:]) //nolint:errcheck
	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], uint64(hashVersionForEntry(e)))
	h.Write(versionBuf[:]) //nolint:errcheck
	writeField(e.Timestamp.Format(time.RFC3339Nano))
	writeField(e.ToolName)
	writeField(e.Verb)
	writeField(e.Target)
	writeField(e.Sensitivity)
	writeField(e.Trust)
	writeField(e.Provenance)
	writeField(e.Decision)
	writeField(e.Reason)
	writeField(e.ContentHash)
	writeField(e.Preview)
	writeField(e.Severity)
	writeField(e.AlertType)
	writeField(e.DetectionID)
	writeField(e.Evidence)
	writeField(e.Agent)
	writeField(e.DiffSummary)
	if e.Restored {
		writeField("true")
	} else {
		writeField("false")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// computeHashV4 extends V3 with the decision latency metric. V3 and earlier
// entries are untouched and still verify under their own functions.
func computeHashV4(e *Entry) string {
	h := sha256.New()
	writeField := func(value string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		h.Write(lenBuf[:])     //nolint:errcheck
		h.Write([]byte(value)) //nolint:errcheck
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:]) //nolint:errcheck
	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], uint64(hashVersionForEntry(e)))
	h.Write(versionBuf[:]) //nolint:errcheck
	writeField(e.Timestamp.Format(time.RFC3339Nano))
	writeField(e.ToolName)
	writeField(e.Verb)
	writeField(e.Target)
	writeField(e.Sensitivity)
	writeField(e.Trust)
	writeField(e.Provenance)
	writeField(e.Decision)
	writeField(e.Reason)
	writeField(e.ContentHash)
	writeField(e.Preview)
	writeField(e.Severity)
	writeField(e.AlertType)
	writeField(e.DetectionID)
	writeField(e.Evidence)
	writeField(e.Agent)
	writeField(e.DiffSummary)
	if e.Restored {
		writeField("true")
	} else {
		writeField("false")
	}
	var latBuf [8]byte
	binary.BigEndian.PutUint64(latBuf[:], uint64(e.LatencyMs))
	h.Write(latBuf[:]) //nolint:errcheck
	return hex.EncodeToString(h.Sum(nil))
}

func hashVersionForEntry(e *Entry) int {
	if e == nil || e.HashVersion == 0 {
		return legacyHashVersion
	}
	return e.HashVersion
}
