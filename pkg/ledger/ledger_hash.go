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
	if hashVersionForEntry(e) <= legacyHashVersion {
		return computeHashV1(e)
	}
	return computeHashV2(e)
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

func hashVersionForEntry(e *Entry) int {
	if e == nil || e.HashVersion == 0 {
		return legacyHashVersion
	}
	return e.HashVersion
}
