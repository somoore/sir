package session

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/somoore/sir/pkg/lease"
)

// ManagedPolicyPathEnvVar selects an org-managed manifest that pins the
// approved lease and hook baselines. The manifest itself must live outside the
// normal user/agent write path; this env var is only the activation seam.
const ManagedPolicyPathEnvVar = "SIR_MANAGED_POLICY_PATH"

// ManagedPolicy is the org-managed trust anchor for restore-only posture.
//
// The hook subtrees are stored verbatim so runtime restore can rebuild the
// exact managed subtree without trusting user-writable canonical backups.
type ManagedPolicy struct {
	Managed               bool                       `json:"managed"`
	PolicyVersion         string                     `json:"policy_version"`
	ManagedLease          *lease.Lease               `json:"managed_lease,omitempty"`
	ManagedLeaseHash      string                     `json:"managed_lease_hash,omitempty"`
	ManagedHooks          map[string]json.RawMessage `json:"managed_hooks,omitempty"`
	ManagedHookHashes     map[string]string          `json:"managed_hook_hashes,omitempty"`
	DisabledLocalCommands []string                   `json:"disabled_local_commands,omitempty"`
	sourcePath            string                     `json:"-"`
}

// ManagedPolicySourcePath returns the path the manifest was loaded from.
func (p *ManagedPolicy) ManagedPolicySourcePath() string {
	if p == nil {
		return ""
	}
	return p.sourcePath
}

// ManagedPolicyPath returns the configured manifest path, or empty when
// managed mode is inactive.
func ManagedPolicyPath() string {
	raw := strings.TrimSpace(os.Getenv(ManagedPolicyPathEnvVar))
	if raw == "" {
		return ""
	}
	if abs, err := filepath.Abs(raw); err == nil {
		return abs
	}
	return raw
}

// LoadManagedPolicy loads and validates the managed-policy manifest. A nil
// policy with nil error means managed mode is inactive.
func LoadManagedPolicy() (*ManagedPolicy, error) {
	path := ManagedPolicyPath()
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read managed policy %s: %w", path, err)
	}
	var policy ManagedPolicy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("parse managed policy %s: %w", path, err)
	}
	policy.sourcePath = path
	if !policy.Managed {
		return nil, fmt.Errorf("managed policy %s is missing managed=true", path)
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("validate managed policy %s: %w", path, err)
	}
	return &policy, nil
}

// Validate checks that the manifest is internally consistent before any local
// sir state is trusted.
func (p *ManagedPolicy) Validate() error {
	if p == nil {
		return fmt.Errorf("nil managed policy")
	}
	if !p.Managed {
		return fmt.Errorf("managed=false")
	}
	if strings.TrimSpace(p.PolicyVersion) == "" {
		return fmt.Errorf("policy_version is required")
	}
	if p.ManagedLease == nil {
		return fmt.Errorf("managed_lease is required")
	}
	if strings.TrimSpace(p.ManagedLeaseHash) == "" {
		return fmt.Errorf("managed_lease_hash is required")
	}
	leaseHash, err := HashManagedLease(p.ManagedLease)
	if err != nil {
		return fmt.Errorf("hash managed_lease: %w", err)
	}
	if leaseHash != p.ManagedLeaseHash {
		return fmt.Errorf("managed_lease hash mismatch")
	}
	if len(p.ManagedHooks) == 0 {
		return fmt.Errorf("managed_hooks is required")
	}
	if len(p.ManagedHookHashes) == 0 {
		return fmt.Errorf("managed_hook_hashes is required")
	}
	for id, raw := range p.ManagedHooks {
		want, ok := p.ManagedHookHashes[id]
		if !ok {
			return fmt.Errorf("managed_hook_hashes missing %q", id)
		}
		got, err := HashManagedHooksSubtree(raw)
		if err != nil {
			return fmt.Errorf("hash managed_hooks[%s]: %w", id, err)
		}
		if got != want {
			return fmt.Errorf("managed_hooks[%s] hash mismatch", id)
		}
	}
	for id := range p.ManagedHookHashes {
		if _, ok := p.ManagedHooks[id]; !ok {
			return fmt.Errorf("managed_hooks missing %q", id)
		}
	}
	return nil
}

// CloneLease returns a deep copy of the managed lease so callers can mutate the
// in-memory value without affecting the manifest copy.
func (p *ManagedPolicy) CloneLease() (*lease.Lease, error) {
	if p == nil || p.ManagedLease == nil {
		return nil, fmt.Errorf("managed_lease is not configured")
	}
	data, err := json.Marshal(p.ManagedLease)
	if err != nil {
		return nil, err
	}
	var out lease.Lease
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// HookSubtree returns the canonical managed subtree bytes for an agent ID.
func (p *ManagedPolicy) HookSubtree(agentID string) ([]byte, bool) {
	if p == nil {
		return nil, false
	}
	raw, ok := p.ManagedHooks[agentID]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, true
}

// IsLocalCommandDisabled reports whether a local policy-widening command is
// disabled by the managed manifest.
func (p *ManagedPolicy) IsLocalCommandDisabled(command string) bool {
	if p == nil {
		return false
	}
	return slices.Contains(p.DisabledLocalCommands, command)
}

// HashManagedLease computes the canonical manifest hash for a managed lease.
func HashManagedLease(l *lease.Lease) (string, error) {
	data, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:]), nil
}

// HashManagedHooksSubtree computes the canonical manifest hash for one managed
// hook subtree.
func HashManagedHooksSubtree(raw []byte) (string, error) {
	canon, err := canonicalizeJSON(raw)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return fmt.Sprintf("%x", sum[:]), nil
}

func canonicalizeJSON(raw []byte) ([]byte, error) {
	var v interface{}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
