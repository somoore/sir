//! Session state tracking.
//!
//! Tracks:
//! - `secret_session`: whether secret-labeled data has been accessed in this session
//! - `recently_read_untrusted`: whether untrusted data was recently read (gates delegation)
//! - `approval_scope`: whether secret approval is session-scoped or turn-scoped
//! - `turn_counter`: current turn number for turn-scoped approval
//! - `inherited_from`: parent session ID for delegation chain tracking

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    /// True once a secret-labeled file has been read (and approved) in this session.
    pub secret_session: bool,
    /// True if untrusted data was recently read (for delegation checks).
    pub recently_read_untrusted: bool,
    /// True if the session has been marked as fatally compromised (e.g., hook config tampered).
    pub deny_all: bool,
    /// Approval scope: "session" (default) or "turn". When "turn", the secret_session
    /// flag is cleared when turn_counter increments.
    pub approval_scope: Option<String>,
    /// Current turn number. Used with turn-scoped approval to detect turn boundaries.
    pub turn_counter: u64,
    /// The turn at which the secret flag was set. Used to clear on turn boundary.
    secret_marked_at_turn: u64,
    /// Parent session ID for delegation chain tracking. When a sub-agent evaluates,
    /// it carries the parent's secret_session flag.
    pub inherited_from: Option<String>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            secret_session: false,
            recently_read_untrusted: false,
            deny_all: false,
            approval_scope: None,
            turn_counter: 0,
            secret_marked_at_turn: 0,
            inherited_from: None,
        }
    }

    /// Mark that secret data has been accessed in this session.
    pub fn mark_secret(&mut self) {
        self.secret_session = true;
        self.secret_marked_at_turn = self.turn_counter;
    }

    /// Mark that untrusted data was recently read.
    pub fn mark_untrusted_read(&mut self) {
        self.recently_read_untrusted = true;
    }

    /// Clear the untrusted read flag (e.g., after a user turn).
    pub fn clear_untrusted_read(&mut self) {
        self.recently_read_untrusted = false;
    }

    /// Mark session as fatally compromised -- all subsequent requests will be denied.
    pub fn mark_deny_all(&mut self) {
        self.deny_all = true;
    }

    /// Advance the turn counter. If approval_scope is "turn" and the turn has
    /// incremented past the turn where secret was marked, clear the secret flag.
    pub fn advance_turn(&mut self, new_turn: u64) {
        if new_turn > self.turn_counter {
            self.turn_counter = new_turn;
            if self.is_turn_scoped() && self.secret_session && new_turn > self.secret_marked_at_turn
            {
                self.secret_session = false;
            }
        }
    }

    /// Set the approval scope.
    pub fn set_approval_scope(&mut self, scope: &str) {
        self.approval_scope = Some(scope.to_string());
    }

    /// Set the inherited_from field for delegation chain tracking.
    pub fn set_inherited_from(&mut self, parent_id: &str) {
        self.inherited_from = Some(parent_id.to_string());
    }

    /// Check whether this session uses turn-scoped approval.
    pub fn is_turn_scoped(&self) -> bool {
        self.approval_scope.as_deref() == Some("turn")
    }
}

impl Default for SessionState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session_clean() {
        let s = SessionState::new();
        assert!(!s.secret_session);
        assert!(!s.recently_read_untrusted);
        assert!(!s.deny_all);
        assert_eq!(s.approval_scope, None);
        assert_eq!(s.turn_counter, 0);
        assert_eq!(s.inherited_from, None);
    }

    #[test]
    fn test_mark_secret() {
        let mut s = SessionState::new();
        s.mark_secret();
        assert!(s.secret_session);
    }

    #[test]
    fn test_mark_untrusted_read() {
        let mut s = SessionState::new();
        s.mark_untrusted_read();
        assert!(s.recently_read_untrusted);
        s.clear_untrusted_read();
        assert!(!s.recently_read_untrusted);
    }

    #[test]
    fn test_deny_all() {
        let mut s = SessionState::new();
        s.mark_deny_all();
        assert!(s.deny_all);
    }

    #[test]
    fn test_secret_session_persists() {
        let mut s = SessionState::new();
        s.mark_secret();
        // Secret session flag is sticky -- cannot be cleared (session scope).
        assert!(s.secret_session);
    }

    #[test]
    fn test_turn_scoped_approval_clears_secret_on_new_turn() {
        let mut s = SessionState::new();
        s.set_approval_scope("turn");
        s.mark_secret(); // marked at turn 0
        assert!(s.secret_session);

        // Same turn: secret persists
        s.advance_turn(0);
        assert!(s.secret_session);

        // New turn: secret clears
        s.advance_turn(1);
        assert!(!s.secret_session);
    }

    #[test]
    fn test_session_scoped_approval_keeps_secret_across_turns() {
        let mut s = SessionState::new();
        s.set_approval_scope("session");
        s.mark_secret();
        assert!(s.secret_session);

        s.advance_turn(1);
        assert!(s.secret_session); // session scope: stays sticky

        s.advance_turn(5);
        assert!(s.secret_session);
    }

    #[test]
    fn test_default_scope_keeps_secret_across_turns() {
        let mut s = SessionState::new();
        // No scope set (None) -- default is session-scoped behavior
        s.mark_secret();
        s.advance_turn(1);
        assert!(s.secret_session);
    }

    #[test]
    fn test_turn_scoped_secret_re_marked_at_later_turn() {
        let mut s = SessionState::new();
        s.set_approval_scope("turn");

        // Mark secret at turn 0, clear at turn 1
        s.mark_secret();
        s.advance_turn(1);
        assert!(!s.secret_session);

        // Re-mark at turn 1
        s.mark_secret();
        assert!(s.secret_session);

        // Still turn 1, secret persists
        s.advance_turn(1);
        assert!(s.secret_session);

        // Turn 2: clears again
        s.advance_turn(2);
        assert!(!s.secret_session);
    }

    #[test]
    fn test_inherited_from() {
        let mut s = SessionState::new();
        assert_eq!(s.inherited_from, None);
        s.set_inherited_from("parent-session-abc");
        assert_eq!(s.inherited_from, Some("parent-session-abc".to_string()));
    }

    #[test]
    fn test_inherited_session_carries_secret_flag() {
        // Simulate a sub-agent inheriting parent's secret state
        let mut parent = SessionState::new();
        parent.mark_secret();

        let mut child = SessionState::new();
        child.secret_session = parent.secret_session;
        child.set_inherited_from("parent-id");

        assert!(child.secret_session);
        assert_eq!(child.inherited_from, Some("parent-id".to_string()));
    }

    #[test]
    fn test_is_turn_scoped() {
        let mut s = SessionState::new();
        assert!(!s.is_turn_scoped());
        s.set_approval_scope("session");
        assert!(!s.is_turn_scoped());
        s.set_approval_scope("turn");
        assert!(s.is_turn_scoped());
    }
}
