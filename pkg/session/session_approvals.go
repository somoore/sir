package session

import (
	"strings"
	"time"
)

// AddApprovalGrant appends a manual approval grant to session state.
func (s *State) AddApprovalGrant(grant ApprovalGrant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	grant.Verb = strings.TrimSpace(grant.Verb)
	grant.Target = strings.TrimSpace(grant.Target)
	if grant.Scope == "" {
		grant.Scope = "once"
	}
	s.ApprovalGrants = append(s.ApprovalGrants, grant)
}

// HasApprovalGrant reports whether a live (non-expired) grant matches the
// verb/target, without consuming it. Used by preflight gates that want to
// defer to the normal ask→grant→allow path when the developer has explicitly
// approved an action (e.g. `sir approve path <secret>`).
func (s *State) HasApprovalGrant(verb, target string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	verb = strings.TrimSpace(verb)
	target = strings.TrimSpace(target)
	now := time.Now()
	for _, grant := range s.ApprovalGrants {
		if !grant.ExpiresAt.IsZero() && now.After(grant.ExpiresAt) {
			continue
		}
		if grant.Verb == verb && (grant.Target == target || grant.Target == "*") {
			return true
		}
	}
	return false
}

// ConsumeApprovalGrant consumes an exact verb/target grant. Grants only apply
// after the policy oracle has returned ASK; callers must not use this to
// override DENY.
func (s *State) ConsumeApprovalGrant(verb, target string) (ApprovalGrant, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	verb = strings.TrimSpace(verb)
	target = strings.TrimSpace(target)
	now := time.Now()

	out := s.ApprovalGrants[:0]
	var matched ApprovalGrant
	used := false
	for _, grant := range s.ApprovalGrants {
		expired := !grant.ExpiresAt.IsZero() && now.After(grant.ExpiresAt)
		if expired {
			continue
		}
		if !used && grant.Verb == verb && (grant.Target == target || grant.Target == "*") {
			matched = grant
			used = true
			if grant.UsesRemaining > 1 {
				grant.UsesRemaining--
				out = append(out, grant)
			} else if grant.UsesRemaining == 0 && grant.Scope == "session" {
				out = append(out, grant)
			}
			continue
		}
		out = append(out, grant)
	}
	s.ApprovalGrants = out
	return matched, used
}
