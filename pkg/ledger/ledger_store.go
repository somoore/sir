package ledger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

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
		if e.Index != i {
			return i, fmt.Errorf("index mismatch at %d: expected %d, got %d", i, i, e.Index)
		}
		if i == 0 {
			if e.PrevHash != genesis {
				return i, fmt.Errorf("genesis entry has wrong prev_hash")
			}
		} else if e.PrevHash != entries[i-1].EntryHash {
			return i, fmt.Errorf("hash chain broken at entry %d", i)
		}
		expected := computeHash(&e)
		if e.EntryHash != expected {
			return i, fmt.Errorf("entry hash mismatch at %d", i)
		}
	}
	return len(entries), nil
}
