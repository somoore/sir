package posture

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/session"
)

// HashGlobalHooksFile computes the combined managed-subtree hash for all
// registered host-agent hook files.
func HashGlobalHooksFile() (string, error) {
	files, err := knownAgentHookFiles()
	if err != nil {
		return "", err
	}
	var chunks [][]byte
	for _, f := range files {
		data, readErr := os.ReadFile(f.AbsPath)
		if readErr != nil {
			if os.IsNotExist(readErr) {
				chunks = append(chunks, nil)
				continue
			}
			return "", readErr
		}

		var toHash []byte
		if subtree, subErr := ExtractManagedSubtree(data, f.SubtreeKey); subErr == nil {
			toHash = subtree
		} else {
			toHash = data
		}
		chunks = append(chunks, toHash)
	}
	return hashHookChunks(chunks)
}

// ManagedGlobalHooksHash computes the managed-policy-backed combined hook hash
// when managed mode is active.
func ManagedGlobalHooksHash() (string, bool, error) {
	policy, err := session.LoadManagedPolicy()
	if err != nil {
		return "", false, err
	}
	if policy == nil {
		return "", false, nil
	}
	files, err := knownAgentHookFiles()
	if err != nil {
		return "", false, err
	}
	chunks := make([][]byte, 0, len(files))
	for _, f := range files {
		raw, ok := policy.HookSubtree(string(agentIDForHookFile(f)))
		if !ok {
			if err := verifyManagedHookCoverage(f, policy); err != nil {
				return "", false, err
			}
			chunks = append(chunks, nil)
			continue
		}
		canon, err := extractCanonicalManagedSubtreeBytes(raw, f.managedSubtreeKey())
		if err != nil {
			return "", false, err
		}
		chunks = append(chunks, canon)
	}
	hash, err := hashHookChunks(chunks)
	return hash, true, err
}

func hashHookChunks(chunks [][]byte) (string, error) {
	h := sha256.New()
	anyFound := false
	for _, chunk := range chunks {
		var lenBuf [8]byte
		n := uint64(len(chunk))
		for i := 0; i < 8; i++ {
			lenBuf[7-i] = byte(n >> (8 * i))
		}
		_, _ = h.Write(lenBuf[:])
		_, _ = h.Write(chunk)
		if len(chunk) > 0 {
			anyFound = true
		}
	}
	if !anyFound {
		return "", os.ErrNotExist
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func HashLeaseFile(projectRoot string) (string, error) {
	leasePath := filepath.Join(session.StateDir(projectRoot), "lease.json")
	data, err := os.ReadFile(leasePath)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h), nil
}

// HashGlobalHooks is the exported compatibility helper used by callers and
// tests that only need the effective hash.
func HashGlobalHooks(_ string) (string, error) {
	return HashGlobalHooksFile()
}

// HashLease returns the active lease hash for a project.
func HashLease(projectRoot string) (string, error) {
	return HashLeaseFile(projectRoot)
}

// VerifyLeaseIntegrity compares the persisted lease hash in session state
// against the current lease file on disk.
func VerifyLeaseIntegrity(projectRoot string, state *session.State) bool {
	if state.LeaseHash == "" {
		return true
	}
	currentHash, err := HashLeaseFile(projectRoot)
	if err != nil {
		return false
	}
	return currentHash == state.LeaseHash
}

// CheckPostureIntegrity compares the current posture file hashes with the
// session baseline.
func CheckPostureIntegrity(projectRoot string, state *session.State, l *lease.Lease) []string {
	currentHashes := HashSentinelFiles(projectRoot, l.PostureFiles)
	return CompareSentinelHashes(state.PostureHashes, currentHashes)
}
