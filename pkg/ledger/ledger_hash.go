package ledger

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"sync"
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
	case v == 4:
		return computeHashV4(e)
	default:
		if key, err := ledgerKey(); err == nil {
			return computeHashV5(e, key)
		}
		// Callers that persist a V5 entry ensure the key first; reaching
		// here means the key is unavailable, so fall back to the unkeyed
		// V4 digest and let Verify surface the mismatch rather than
		// writing a hash nobody can reproduce.
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

// hmacState is a reusable keyed hasher. Verify computes one hash per ledger
// entry, so allocating a fresh HMAC/SHA-256 state per entry roughly doubles
// the allocations of the whole operation.
type hmacState struct {
	key []byte
	mac hash.Hash
}

// ledgerHMACGuard serializes reuse of one keyed hasher. Verification is a
// sequential walk and hooks run in separate processes, so a single guarded
// state avoids allocating an HMAC/SHA-256 context per ledger entry.
type hmacGuard struct {
	mu    sync.Mutex
	state hmacState
}

var ledgerHMACGuard hmacGuard

func (g *hmacGuard) acquire(key []byte) *hmacState {
	g.mu.Lock()
	if g.state.mac == nil || !bytes.Equal(g.state.key, key) {
		g.state.key = append(g.state.key[:0], key...)
		g.state.mac = hmac.New(sha256.New, key)
	} else {
		g.state.mac.Reset()
	}
	return &g.state
}

func (g *hmacGuard) release() { g.mu.Unlock() }

// computeHashV5 extends V4 with HMAC-SHA256 under the per-install key at
// ~/.sir/ledger.key. An actor who can rewrite ledger.jsonl but cannot read
// the key cannot recompute a consistent chain, so deleting or rewriting
// entries is detected rather than looking like a clean ledger. V1-V4 entries
// keep verifying under their original unkeyed functions.
func computeHashV5(e *Entry, key []byte) string {
	// Build the length-prefixed canonical message once and feed it to HMAC
	// in a single Write. Writing field-by-field through the hash.Hash
	// interface makes each string→[]byte conversion escape, which doubled
	// the allocations of a ledger verification walk.
	buf := make([]byte, 0, 512)
	appendField := func(value string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(value)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, value...)
	}
	appendField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	buf = append(buf, idxBuf[:]...)
	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], uint64(hashVersionForEntry(e)))
	buf = append(buf, versionBuf[:]...)
	appendField(e.Timestamp.Format(time.RFC3339Nano))
	appendField(e.ToolName)
	appendField(e.Verb)
	appendField(e.Target)
	appendField(e.Sensitivity)
	appendField(e.Trust)
	appendField(e.Provenance)
	appendField(e.Decision)
	appendField(e.Reason)
	appendField(e.ContentHash)
	appendField(e.Preview)
	appendField(e.Severity)
	appendField(e.AlertType)
	appendField(e.DetectionID)
	appendField(e.Evidence)
	appendField(e.Agent)
	appendField(e.DiffSummary)
	if e.Restored {
		appendField("true")
	} else {
		appendField("false")
	}
	var latBuf [8]byte
	binary.BigEndian.PutUint64(latBuf[:], uint64(e.LatencyMs))
	buf = append(buf, latBuf[:]...)

	state := ledgerHMACGuard.acquire(key)
	defer ledgerHMACGuard.release()
	state.mac.Write(buf) //nolint:errcheck
	return hex.EncodeToString(state.mac.Sum(nil))
}
