package session

import "github.com/somoore/sir/pkg/policy"

// MarkUntrustedRead flags that untrusted content was recently read.
func (s *State) MarkUntrustedRead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RecentlyReadUntrusted = true
}

// ClearUntrustedRead clears the recently-read-untrusted flag.
func (s *State) ClearUntrustedRead() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.RecentlyReadUntrusted = false
}

// SetDenyAll triggers session-fatal deny-all mode.
func (s *State) SetDenyAll(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.DenyAll = true
	s.DenyAllReason = reason
}

// SetPendingInstall records a pending install for sentinel comparison.
func (s *State) SetPendingInstall(cmd, manager string, sentinelHashes map[string]string, lockfileHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingInstall = &PendingInstall{
		Command:        cmd,
		Manager:        manager,
		SentinelHashes: sentinelHashes,
		LockfileHash:   lockfileHash,
	}
}

// ClearPendingInstall removes the pending install record.
func (s *State) ClearPendingInstall() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingInstall = nil
}

// RaisePosture raises the session posture level. Posture can only go up.
func (s *State) RaisePosture(level policy.PostureState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if postureOrd(level) > postureOrd(s.Posture) {
		s.Posture = level
	}
}

// AddTaintedMCPServer records an MCP server that returned injection signals.
func (s *State) AddTaintedMCPServer(serverName string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.TaintedMCPServers {
		if existing == serverName {
			return
		}
	}
	s.TaintedMCPServers = append(s.TaintedMCPServers, serverName)
}

// AddMCPInjectionSignal records an injection signal pattern name.
func (s *State) AddMCPInjectionSignal(pattern string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.MCPInjectionSignals {
		if existing == pattern {
			return
		}
	}
	s.MCPInjectionSignals = append(s.MCPInjectionSignals, pattern)
}

// IsMCPServerTainted returns true if the given server has been flagged for injection.
func (s *State) IsMCPServerTainted(serverName string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.TaintedMCPServers {
		if t == serverName {
			return true
		}
	}
	return false
}

// SetPendingInjectionAlert flags that an injection was detected in PostToolUse.
func (s *State) SetPendingInjectionAlert(detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingInjectionAlert = true
	s.InjectionAlertDetail = detail
}

// ClearPendingInjectionAlert clears the injection alert after PreToolUse has shown it.
func (s *State) ClearPendingInjectionAlert() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PendingInjectionAlert = false
	s.InjectionAlertDetail = ""
}

// postureOrd returns a numeric ordering for posture levels.
func postureOrd(level policy.PostureState) int {
	switch level {
	case policy.PostureStateCritical:
		return 3
	case policy.PostureStateElevated:
		return 2
	case policy.PostureStateNormal:
		return 1
	default:
		return 0
	}
}
