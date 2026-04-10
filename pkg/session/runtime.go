package session

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RuntimeContainment captures the active `sir run` launch context so status
// surfaces outside the sandbox can explain the effective host-agent boundary.
type RuntimeContainment struct {
	AgentID             string    `json:"agent_id"`
	Mode                string    `json:"mode"`
	ProxyURL            string    `json:"proxy_url,omitempty"`
	SOCKSProxyURL       string    `json:"socks_proxy_url,omitempty"`
	ProxyProtocols      []string  `json:"proxy_protocols,omitempty"`
	AllowedHosts        []string  `json:"allowed_hosts,omitempty"`
	AllowedDestinations []string  `json:"allowed_destinations,omitempty"`
	MaskedHostSockets   []string  `json:"masked_host_sockets,omitempty"`
	ScrubbedEnvVars     []string  `json:"scrubbed_env_vars,omitempty"`
	DegradedReasons     []string  `json:"degraded_reasons,omitempty"`
	ShadowStateHome     string    `json:"shadow_state_home,omitempty"`
	StartedAt           time.Time `json:"started_at"`
	HeartbeatAt         time.Time `json:"heartbeat_at,omitempty"`
	LauncherPID         int       `json:"launcher_pid,omitempty"`
	AgentPID            int       `json:"agent_pid,omitempty"`
}

// RuntimeContainmentHealth is the operator-facing state of the recorded
// runtime-containment descriptor.
type RuntimeContainmentHealth string

const (
	RuntimeContainmentActive   RuntimeContainmentHealth = "active"
	RuntimeContainmentDegraded RuntimeContainmentHealth = "degraded"
	RuntimeContainmentStale    RuntimeContainmentHealth = "stale"
	RuntimeContainmentLegacy   RuntimeContainmentHealth = "legacy"
)

const (
	runtimeDegradedReasonProxyShaped       = "proxy-shaped enforcement: direct non-proxy sockets remain outside the exact-destination boundary on macOS"
	runtimeDegradedReasonMaskedHostBridges = "launch inherited host-control sockets that had to be masked inside containment"
	runtimeDegradedReasonScrubbedHostEnv   = "launch inherited host-control env that had to be scrubbed before containment"
)

// RuntimeContainmentInspection combines the persisted runtime descriptor with
// the derived health classification used by status/doctor output.
type RuntimeContainmentInspection struct {
	Info   *RuntimeContainment
	Health RuntimeContainmentHealth
	Reason string
}

// StatePathUnder returns the session.json path for a project rooted under the
// provided home directory.
func StatePathUnder(home, projectRoot string) string {
	return filepath.Join(StateDirUnder(home, projectRoot), "session.json")
}

// LoadFromHome reads session state from an explicit home root instead of the
// ambient process environment. Used by status paths that need to inspect the
// shadow state created by `sir run`.
func LoadFromHome(home, projectRoot string) (*State, error) {
	data, err := os.ReadFile(StatePathUnder(home, projectRoot))
	if err != nil {
		return nil, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmpFile.Name()
	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Chmod(perm); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return nil
}

// EffectiveProxyProtocols returns the protocol surface advertised by the
// runtime containment descriptor. Older descriptors may only have ProxyURL.
func (r *RuntimeContainment) EffectiveProxyProtocols() []string {
	if r == nil {
		return nil
	}
	if len(r.ProxyProtocols) > 0 {
		return append([]string(nil), r.ProxyProtocols...)
	}
	protocols := make([]string, 0, 2)
	if r.ProxyURL != "" {
		protocols = append(protocols, "http-connect")
	}
	if r.SOCKSProxyURL != "" {
		protocols = append(protocols, "socks5")
	}
	return protocols
}

// EffectiveDegradedReasons returns the persisted degraded reasons plus any
// backward-compatible inference from older runtime descriptors.
func (r *RuntimeContainment) EffectiveDegradedReasons() []string {
	if r == nil {
		return nil
	}
	reasons := append([]string(nil), r.DegradedReasons...)
	addReason := func(reason string) {
		reason = strings.TrimSpace(reason)
		if reason == "" {
			return
		}
		for _, existing := range reasons {
			if existing == reason {
				return
			}
		}
		reasons = append(reasons, reason)
	}

	if r.Mode == "darwin_local_proxy" {
		addReason(runtimeDegradedReasonProxyShaped)
	}
	if len(r.MaskedHostSockets) > 0 {
		addReason(runtimeDegradedReasonMaskedHostBridges)
	}
	if len(r.ScrubbedEnvVars) > 0 {
		addReason(runtimeDegradedReasonScrubbedHostEnv)
	}
	return reasons
}
