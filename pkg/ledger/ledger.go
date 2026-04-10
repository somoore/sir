// Package ledger implements an append-only hash-chained ledger for sir.
// The ledger stores paths, labels, hashes, verdicts, timestamps, and optional
// redacted investigation evidence. Raw secrets are never persisted.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/somoore/sir/pkg/session"
)

// Entry is a single ledger entry.
type Entry struct {
	Index       int       `json:"index"`
	Timestamp   time.Time `json:"timestamp"`
	PrevHash    string    `json:"prev_hash"`
	EntryHash   string    `json:"entry_hash"`
	HashVersion int       `json:"hash_version,omitempty"`

	// Tool call context
	ToolName string `json:"tool_name"`
	Verb     string `json:"verb"`
	Target   string `json:"target"`

	// Labels assigned
	Sensitivity string `json:"sensitivity,omitempty"`
	Trust       string `json:"trust,omitempty"`
	Provenance  string `json:"provenance,omitempty"`

	// Verdict
	Decision string `json:"decision"` // allow, deny, ask
	Reason   string `json:"reason"`

	// Optional metadata
	ContentHash string `json:"content_hash,omitempty"` // SHA-256 of content, never content itself
	Preview     string `json:"preview,omitempty"`      // first 80 chars, redacted if secret
	Severity    string `json:"severity,omitempty"`     // HIGH, MEDIUM, LOW
	AlertType   string `json:"alert_type,omitempty"`   // sentinel_mutation, posture_tamper, etc.
	Evidence    string `json:"evidence,omitempty"`     // optional redacted investigation evidence
	Agent       string `json:"agent,omitempty"`        // target agent id for tamper alerts
	DiffSummary string `json:"diff_summary,omitempty"` // concise diff summary for posture alerts
	Restored    bool   `json:"restored,omitempty"`     // whether auto-restore succeeded
}

const (
	legacyHashVersion  = 1
	currentHashVersion = 2
)

// LedgerPath returns the path to the ledger file for a project.
func LedgerPath(projectRoot string) string {
	return filepath.Join(session.StateDir(projectRoot), "ledger.jsonl")
}

// withLedgerLockMode acquires a file lock on ledgerPath+".lock", calls fn, and
// releases the lock afterward. Exclusive locks serialize writers, while shared
// locks keep readers from observing partially written JSON lines.
func withLedgerLockMode(ledgerPath string, mode int, fn func() error) error {
	lockPath := ledgerPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open lock file: %w", err)
	}
	defer lockFile.Close()
	if err := syscall.Flock(int(lockFile.Fd()), mode); err != nil {
		return fmt.Errorf("acquire lock: %w", err)
	}
	defer syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN) //nolint:errcheck
	return fn()
}

func withLedgerLock(ledgerPath string, fn func() error) error {
	return withLedgerLockMode(ledgerPath, syscall.LOCK_EX, fn)
}

// Append adds an entry to the ledger with hash chaining.
// A file-level lock (ledger.jsonl.lock) prevents concurrent writers from
// interleaving the read-last-hash and write steps.
func Append(projectRoot string, entry *Entry) error {
	ledgerPath := LedgerPath(projectRoot)
	if err := os.MkdirAll(filepath.Dir(ledgerPath), 0o700); err != nil {
		return err
	}

	return withLedgerLock(ledgerPath, func() error {
		// Read last entry to get prev_hash
		prevHash := "0000000000000000000000000000000000000000000000000000000000000000"
		lastIndex := -1

		if entries, err := readAllUnlocked(ledgerPath); err == nil && len(entries) > 0 {
			last := entries[len(entries)-1]
			prevHash = last.EntryHash
			lastIndex = last.Index
		}

		entry.Index = lastIndex + 1
		entry.Timestamp = time.Now()
		entry.PrevHash = prevHash
		if entry.HashVersion == 0 {
			entry.HashVersion = currentHashVersion
		}
		sanitizeEntry(entry)

		// Compute entry hash (hash of prev_hash + serialized entry without entry_hash)
		entry.EntryHash = computeHash(entry)

		data, err := json.Marshal(entry)
		if err != nil {
			return err
		}

		f, err := os.OpenFile(ledgerPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = f.Write(append(data, '\n'))
		return err
	})
}

func sanitizeEntry(entry *Entry) {
	if entry == nil {
		return
	}
	entry.Reason = RedactString(entry.Reason)
	if entry.Sensitivity == "secret" {
		entry.Preview = RedactPreview(entry.Preview, true)
	} else {
		entry.Preview = RedactContent(entry.Preview, 256)
	}
	entry.Evidence = RedactEvidence(entry.Evidence)
	entry.DiffSummary = RedactString(entry.DiffSummary)
}

// ReadAll reads all entries from the ledger.
func ReadAll(projectRoot string) ([]Entry, error) {
	ledgerPath := LedgerPath(projectRoot)
	if _, err := os.Stat(filepath.Dir(ledgerPath)); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var entries []Entry
	err := withLedgerLockMode(ledgerPath, syscall.LOCK_SH, func() error {
		var readErr error
		entries, readErr = readAllUnlocked(ledgerPath)
		return readErr
	})
	return entries, err
}

func readAllUnlocked(ledgerPath string) ([]Entry, error) {
	f, err := os.Open(ledgerPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var entries []Entry
	scanner := bufio.NewScanner(f)
	// Increase buffer for long lines
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		var e Entry
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("corrupt ledger entry: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, scanner.Err()
}

// Verify checks the hash chain integrity of the ledger.
func Verify(projectRoot string) (int, error) {
	entries, err := ReadAll(projectRoot)
	if err != nil {
		return 0, err
	}
	if len(entries) == 0 {
		return 0, nil
	}

	genesis := "0000000000000000000000000000000000000000000000000000000000000000"
	for i, e := range entries {
		// Check index
		if e.Index != i {
			return i, fmt.Errorf("index mismatch at %d: expected %d, got %d", i, i, e.Index)
		}
		// Check prev_hash
		if i == 0 {
			if e.PrevHash != genesis {
				return i, fmt.Errorf("genesis entry has wrong prev_hash")
			}
		} else {
			if e.PrevHash != entries[i-1].EntryHash {
				return i, fmt.Errorf("hash chain broken at entry %d", i)
			}
		}
		// Verify entry hash
		expected := computeHash(&e)
		if e.EntryHash != expected {
			return i, fmt.Errorf("entry hash mismatch at %d", i)
		}
	}
	return len(entries), nil
}

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
	writeField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:])
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
	writeField := func(s string) {
		var lenBuf [8]byte
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
		h.Write(lenBuf[:])
		h.Write([]byte(s))
	}
	writeField(e.PrevHash)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], uint64(e.Index))
	h.Write(idxBuf[:])
	var versionBuf [8]byte
	binary.BigEndian.PutUint64(versionBuf[:], uint64(hashVersionForEntry(e)))
	h.Write(versionBuf[:])
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

// GetLastEntry returns the most recent ledger entry, or nil if the ledger is empty.
func GetLastEntry(projectRoot string) (*Entry, error) {
	entries, err := ReadAll(projectRoot)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, nil
	}
	e := entries[len(entries)-1]
	return &e, nil
}

// GetEntryByIndex returns a specific ledger entry by index.
// Returns nil if the index is out of range.
func GetEntryByIndex(projectRoot string, index int) (*Entry, []Entry, error) {
	entries, err := ReadAll(projectRoot)
	if err != nil {
		return nil, nil, err
	}
	if index < 0 || index >= len(entries) {
		return nil, entries, fmt.Errorf("index %d out of range (ledger has %d entries)", index, len(entries))
	}
	e := entries[index]
	return &e, entries, nil
}

// FindCausalSecretRead scans backwards from the given index to find the ledger
// entry that first set the session's secret flag. This is typically a read_ref
// with sensitivity=secret and decision=ask (approved by the developer), or an
// env_read that triggered session secret marking.
// Returns nil if no causal secret read is found.
func FindCausalSecretRead(entries []Entry, beforeIndex int) *Entry {
	for i := beforeIndex - 1; i >= 0; i-- {
		e := entries[i]
		// A secret file read that was approved (ask = developer said yes)
		if e.Sensitivity == "secret" && (e.Decision == "ask" || e.Decision == "allow") {
			return &e
		}
		// An env_read that was approved
		if e.Verb == "env_read" && (e.Decision == "ask" || e.Decision == "allow") {
			return &e
		}
	}
	return nil
}

// FindRelatedEntries finds entries related to a given entry for causal chain construction.
// It returns entries that share the same session context (same target, same verb category,
// or entries that contributed to the current security state).
func FindRelatedEntries(entries []Entry, targetIndex int) []Entry {
	if targetIndex < 0 || targetIndex >= len(entries) {
		return nil
	}
	target := entries[targetIndex]
	var related []Entry

	// For deny/block decisions, find the causal secret read
	if target.Decision == "deny" {
		causal := FindCausalSecretRead(entries, targetIndex)
		if causal != nil {
			related = append(related, *causal)
		}
	}

	// Find the session secret marking event (if this entry is in a secret session)
	// Look for entries that changed the session state
	for i := 0; i < targetIndex; i++ {
		e := entries[i]
		// Session-marking events relevant to the target
		if e.Sensitivity == "secret" && (e.Decision == "ask" || e.Decision == "allow") {
			// Don't duplicate if already found as causal
			alreadyIncluded := false
			for _, r := range related {
				if r.Index == e.Index {
					alreadyIncluded = true
					break
				}
			}
			if !alreadyIncluded {
				related = append(related, e)
			}
		}
	}

	return related
}
