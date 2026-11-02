package ledger

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// ledgerKeyPath is deliberately outside ~/.sir/projects/<hash>: the keyed
// chain only means something if the key is not in the same directory the
// audited agent can edit. It is per install, not per project.
func ledgerKeyPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("SIR_STATE_HOME")); override != "" {
		return filepath.Join(override, ".sir", "ledger.key"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".sir", "ledger.key"), nil
}

var (
	ledgerKeyMu    sync.Mutex
	ledgerKeyCache []byte
)

// ledgerKey returns the per-install HMAC key, creating it (0600) on first
// use. A missing key is never silently replaced: replacing it would make old
// entries verify against a new key only if the attacker also rewrote them,
// so callers that need V5 verification get a clear error instead.
func ledgerKey() ([]byte, error) {
	ledgerKeyMu.Lock()
	defer ledgerKeyMu.Unlock()
	if len(ledgerKeyCache) == 32 {
		return ledgerKeyCache, nil
	}
	path, err := ledgerKeyPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err == nil {
		key, decErr := decodeLedgerKey(data)
		if decErr != nil {
			return nil, fmt.Errorf("%s: %w", path, decErr)
		}
		ledgerKeyCache = key
		return key, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate ledger key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	encoded := []byte(hex.EncodeToString(key) + "\n")
	// Publish the key only once it is fully written: write a private temp
	// file in the same directory, then hard-link it into place. Link fails
	// if the key already exists, so another process's key is never
	// replaced, and a concurrent reader never sees a partial file.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".ledger.key.*")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(encoded); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return nil, err
	}
	if err := os.Link(tmpPath, path); err != nil {
		if os.IsExist(err) {
			// Lost a creation race; read the winner's key.
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil, readErr
			}
			key, decErr := decodeLedgerKey(data)
			if decErr != nil {
				return nil, fmt.Errorf("%s: %w", path, decErr)
			}
			ledgerKeyCache = key
			return key, nil
		}
		return nil, err
	}

	ledgerKeyCache = key
	return key, nil
}

func decodeLedgerKey(data []byte) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("ledger key is not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("ledger key must be 32 bytes, got %d", len(key))
	}
	return key, nil
}
