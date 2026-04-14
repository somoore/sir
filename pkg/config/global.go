// Package config loads and persists the sir global configuration that
// applies across all projects.
//
// The config file is ~/.sir/config.json. It stores user preferences that
// influence how `sir install`, MCP approval, and quarantine behave. The
// config is intentionally minimal; per-project policy continues to live in
// lease files under ~/.sir/projects/<hash>/.
//
// Fail-closed semantics: corrupted JSON returns an error. Missing file
// returns defaults so a fresh install or upgrade does not trip the guard.
// Callers that want to treat missing as first-run should use
// IsFirstInstall() which inspects an independent sentinel (the binary
// manifest).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MCPTrustPosture controls how `sir install` treats newly-discovered MCP
// servers. Values are compared as strings so the JSON file stays
// human-readable.
type MCPTrustPosture string

const (
	// PostureStrict: discovered MCP servers are recorded but require
	// explicit `sir mcp approve <name>` before ApprovedMCPServers is
	// widened. First use hits the existing unknown-server ask gate.
	PostureStrict MCPTrustPosture = "strict"

	// PostureStandard: discovered MCP servers are auto-added to
	// ApprovedMCPServers (the pre-existing behavior of `sir install`).
	// The verb pipeline still applies — credential scan, URL allow-host,
	// etc. continue to run. This is the "balanced default" for users who
	// already installed sir before this config file existed.
	PostureStandard MCPTrustPosture = "standard"

	// PostureLoose is a reserved synonym for permissive intent. Treated
	// identically to PostureStandard for now; documented separately so a
	// future release can relax behavior further without reusing
	// Standard's meaning.
	PostureLoose MCPTrustPosture = "permissive"
)

// Config is the on-disk shape of ~/.sir/config.json. New fields must be
// added with JSON tags matching the existing kebab-case style. Unknown
// fields deserialize silently to allow forward compatibility on upgrade.
type Config struct {
	MCPTrustPosture MCPTrustPosture `json:"mcp_trust_posture,omitempty"`

	// MCPOnboardingWindowHours is how long an MCP approval remains "fresh"
	// for the onboarding gate. While a server's approval is fresh AND its
	// session call count is below MCPOnboardingCallCount, calls that would
	// silently allow are bumped to ask. Default is 24. Set to a negative
	// value to disable the gate; 0 and missing are treated as "use default"
	// because Go JSON cannot distinguish missing from zero.
	MCPOnboardingWindowHours int `json:"mcp_onboarding_window_hours,omitempty"`

	// MCPOnboardingCallCount is the per-session call threshold for the
	// onboarding gate. Once the server has been called this many times in
	// the current session, the gate stops firing for it even if the wall
	// clock window is still open. Default is 20. Negative disables; 0 and
	// missing use the default.
	//
	// Scope note: this is per-session, not per-approval. Each new agent
	// session resets the count. That is intentional — the counter is a
	// friction tool, not a security control, so "fresh session →
	// re-acquaint" is the right semantic. Do not treat the count as
	// cumulative trust evidence.
	MCPOnboardingCallCount int `json:"mcp_onboarding_call_count,omitempty"`

	// MCPDeepVerbGating enables best-effort re-classification of MCP tool
	// arguments into native verbs so they hit the normal verb pipeline.
	// When enabled, a `command` field routes through the shell classifier
	// and a `file_path` field routes through the posture/sensitive path
	// classifiers. Default is false in v1 to avoid false positives and
	// noisy prompts; v2 may flip this default after telemetry confirms
	// the pattern holds in practice.
	//
	// Scope honesty: this only catches honest MCP servers that expose
	// shell/filesystem primitives under conventional field names. A
	// malicious MCP can rename fields, base64-encode payloads, or
	// construct dangerous commands server-side. This flag does not make
	// an approved MCP safe — containment for malicious MCPs remains
	// `sir mcp-proxy` + OS sandbox.
	MCPDeepVerbGating bool `json:"mcp_deep_verb_gating,omitempty"`

	// UpdatedAt is a local timestamp recorded on Save. Used for telemetry
	// and diagnostic commands (`sir doctor`) to surface recent config
	// writes. Not load-bearing for any policy decision.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

const (
	defaultOnboardingWindowHours = 24
	defaultOnboardingCallCount   = 20
)

// Defaults returns the baseline config applied when ~/.sir/config.json is
// absent. Existing users upgrading from a version without this file get
// PostureStandard so their behavior does not change on upgrade. Fresh
// installs tighten the default in Save via IsFirstInstall detection.
func Defaults() *Config {
	return &Config{
		MCPTrustPosture:          PostureStandard,
		MCPOnboardingWindowHours: defaultOnboardingWindowHours,
		MCPOnboardingCallCount:   defaultOnboardingCallCount,
	}
}

// Path returns the absolute path to the global config file.
func Path() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".sir", "config.json"), nil
}

// Load reads ~/.sir/config.json. Missing file returns Defaults() and
// ok=false; a successful read returns the parsed config and ok=true.
// Parse errors fail closed (return error) — a corrupted config must not
// silently revert to defaults, which would widen trust unexpectedly.
func Load() (*Config, bool, error) {
	path, err := Path()
	if err != nil {
		return Defaults(), false, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Defaults(), false, nil
		}
		return Defaults(), false, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Defaults(), false, fmt.Errorf("parse config: %w", err)
	}
	if c.MCPTrustPosture == "" {
		c.MCPTrustPosture = PostureStandard
	} else if !IsValidPosture(string(c.MCPTrustPosture)) {
		// Fail closed on unknown posture values. Without this check, a
		// typo like "strcit" would slip through to install's switch
		// default (treated as "standard" → auto-approve), silently
		// widening MCP trust. Force the user to fix the config.
		return Defaults(), false, fmt.Errorf(
			"parse config: unknown mcp_trust_posture %q (valid: strict, standard, permissive)",
			string(c.MCPTrustPosture),
		)
	}
	if c.MCPOnboardingWindowHours == 0 {
		c.MCPOnboardingWindowHours = defaultOnboardingWindowHours
	}
	if c.MCPOnboardingCallCount == 0 {
		c.MCPOnboardingCallCount = defaultOnboardingCallCount
	}
	return &c, true, nil
}

// OnboardingEnabled reports whether the onboarding gate should fire for
// any call. Returns true only if both knobs are positive — either negative
// disables the gate entirely.
func (c *Config) OnboardingEnabled() bool {
	return c.MCPOnboardingWindowHours > 0 && c.MCPOnboardingCallCount > 0
}

// Save writes the config atomically. Creates ~/.sir if absent.
func (c *Config) Save() error {
	path, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	c.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "config-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// IsFirstInstall returns true when the binary manifest is absent. Used by
// `sir install` to decide whether to default to PostureStrict (fresh
// install, no habits to preserve) or PostureStandard (upgrade). Kept in
// this package rather than core to avoid a circular import; the manifest
// path is stable enough to recompute here.
func IsFirstInstall() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	manifestPath := filepath.Join(home, ".sir", "binary-manifest.json")
	if _, err := os.Stat(manifestPath); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// IsValidPosture reports whether s is a recognized posture value.
func IsValidPosture(s string) bool {
	switch MCPTrustPosture(s) {
	case PostureStrict, PostureStandard, PostureLoose:
		return true
	}
	return false
}
