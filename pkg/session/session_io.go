package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/somoore/sir/pkg/policy"
)

// Load reads session state from disk.
func Load(projectRoot string) (*State, error) {
	data, err := os.ReadFile(StatePath(projectRoot))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	if s.SchemaVersion == 0 {
		s.SchemaVersion = policy.SessionSchemaVersion
	}
	if s.SchemaVersion != policy.SessionSchemaVersion {
		return nil, fmt.Errorf("unsupported session schema version: %d", s.SchemaVersion)
	}
	return &s, nil
}

// Save persists session state to disk using atomic rename.
func (s *State) Save() error {
	s.mu.Lock()
	savedHash := s.SessionHash
	s.SchemaVersion = policy.SessionSchemaVersion
	s.SessionHash = ""
	hashData, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		s.SessionHash = savedHash
		s.mu.Unlock()
		return err
	}
	h := sha256.Sum256(hashData)
	s.SessionHash = hex.EncodeToString(h[:])
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}

	dir := StateDir(s.ProjectRoot)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	finalPath := StatePath(s.ProjectRoot)
	tmpFile, err := os.CreateTemp(dir, "session-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	tmpFile.Close()
	return os.Rename(tmpPath, finalPath)
}
