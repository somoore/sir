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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
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
	if _, err := f.Write(encoded); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	_ = os.Chmod(path, 0o600)

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
