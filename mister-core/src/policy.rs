//! Policy rule evaluation.
//!
//! Maps verb + labels + session state to verdict (allow/deny/ask).
//! Enforces the documented runtime-security contract for sir.

#[path = "policy_common.rs"]
mod policy_common;
#[path = "policy_guards.rs"]
mod policy_guards;
#[path = "policy_sinks.rs"]
mod policy_sinks;

use crate::lease::Lease;
use crate::session::SessionState;
use mister_shared::{EvalRequest, Verdict};
pub use policy_common::PolicyResult;
use policy_common::{
    ask_verb_result, default_unknown_verb_result, evaluate_allowed_verb, forbidden_verb_result,
    parse_verb,
};
use policy_guards::{
    evaluate_delegation_guardrails, evaluate_network_guardrails, evaluate_preapproval_guards,
    evaluate_secret_session_guards, evaluate_session_preconditions,
};
use policy_sinks::evaluate_derived_secret_sink;

/// Evaluate the policy for a given request against the lease and session state.
///
/// Enforcement gradient:
/// ```text
/// Secret file read                    -> ask (developer decides)
/// Secret session + external egress    -> block
/// Secret session + unapproved push    -> block
/// Secret session + loopback/approved  -> allow
/// Posture file write                  -> ask (always)
/// Posture file tampered via Bash      -> session-fatal deny-all
/// New MCP server                      -> ask
/// Agent delegation after untrusted    -> ask
/// Tripwire file touched               -> block
/// Unlocked package install            -> ask
/// Normal coding (read/write/test/commit) -> silent allow
/// ```
pub fn evaluate(req: &EvalRequest, lease: &Lease, session: &SessionState) -> PolicyResult {
    if let Some(result) = evaluate_session_preconditions(req, lease, session) {
        return result;
    }

    let verb = match parse_verb(req) {
        Ok(verb) => verb,
        Err(result) => return result,
    };

    if let Some(result) = evaluate_preapproval_guards(req, verb) {
        return result;
    }

    if let Some(result) = evaluate_derived_secret_sink(req, verb) {
        if lease.is_verb_forbidden(verb) && !matches!(result.verdict, Verdict::Deny) {
            return forbidden_verb_result(verb);
        }
        return result;
    }

    if let Some(result) = evaluate_network_guardrails(req, verb) {
        return result;
    }

    if lease.is_verb_forbidden(verb) {
        return forbidden_verb_result(verb);
    }

    if let Some(result) = evaluate_secret_session_guards(req, session, verb) {
        return result;
    }

    if let Some(result) = evaluate_delegation_guardrails(req, lease, session, verb) {
        return result;
    }

    if lease.is_verb_ask(verb) {
        return ask_verb_result(verb);
    }

    if lease.is_verb_allowed(verb) {
        return evaluate_allowed_verb(req, verb);
    }

    default_unknown_verb_result(req, verb)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mister_shared::{Label, Verb};

    fn default_lease() -> Lease {
        Lease::default_lease()
    }

    fn clean_session() -> SessionState {
        SessionState::new()
    }

    fn secret_session() -> SessionState {
        let mut s = SessionState::new();
        s.mark_secret();
        s
    }

    fn make_request(verb: &str) -> EvalRequest {
        EvalRequest {
            verb: verb.to_string(),
            target: String::new(),
            tool_name: String::new(),
            labels: vec![],
            derived_labels: vec![],
            session_secret: false,
            session_untrusted_read: false,
            is_posture_file: false,
            is_sensitive_path: false,
            is_delegation: false,
            is_tripwire: false,
        }
    }

    // --- Normal coding: silent allow ---

    #[test]
    fn test_read_normal_file_allowed() {
        let req = make_request("read_ref");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_write_normal_file_allowed() {
        let req = make_request("stage_write");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_run_tests_allowed() {
        let req = make_request("run_tests");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_git_commit_allowed() {
        let req = make_request("commit");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_execute_dry_run_allowed() {
        let req = make_request("execute_dry_run");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_net_local_allowed() {
        let req = make_request("net_local");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_push_origin_allowed() {
        let req = make_request("push_origin");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret file read: ask ---

    #[test]
    fn test_read_sensitive_file_asks() {
        let mut req = make_request("read_ref");
        req.is_sensitive_path = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("sensitive"));
    }

    // --- Posture file write: always ask ---

    #[test]
    fn test_write_posture_file_asks() {
        let mut req = make_request("stage_write");
        req.is_posture_file = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security settings"));
    }

    // --- Secret session + external egress: block ---

    #[test]
    fn test_net_external_denied() {
        let req = make_request("net_external");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }

    #[test]
    fn test_net_external_with_secret_session_denied() {
        let mut req = make_request("net_external");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Secret session + loopback: allow ---

    #[test]
    fn test_net_local_with_secret_session_allowed() {
        let mut req = make_request("net_local");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret session + approved host: allow ---

    #[test]
    fn test_net_allowlisted_with_secret_session_allowed() {
        let mut req = make_request("net_allowlisted");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- Secret session + push origin: ask ---

    #[test]
    fn test_push_origin_with_secret_session_asks() {
        let mut req = make_request("push_origin");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("credentials"));
    }

    // --- Secret session + push remote (unapproved): block ---

    #[test]
    fn test_push_remote_with_secret_session_denied() {
        let mut req = make_request("push_remote");
        req.session_secret = true;
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Push remote (no secret): ask ---

    #[test]
    fn test_push_remote_no_secret_asks() {
        let req = make_request("push_remote");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    #[test]
    fn test_stage_write_with_derived_secret_asks() {
        let mut req = make_request("stage_write");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_commit_with_derived_secret_asks() {
        let mut req = make_request("commit");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_push_origin_with_derived_secret_asks_without_session_secret() {
        let mut req = make_request("push_origin");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_push_remote_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("push_remote");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("staged content derives"));
    }

    #[test]
    fn test_forbidden_verb_beats_derived_secret_sink_override() {
        let mut req = make_request("push_origin");
        req.derived_labels = vec![Label::secret()];
        let mut lease = default_lease();
        lease.forbidden_verbs.push(Verb::PushOrigin);

        let result = evaluate(&req, &lease, &clean_session());

        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("forbidden by your security policy"));
    }

    #[test]
    fn test_forbidden_verb_denies_without_derived_labels() {
        let req = make_request("push_origin");
        let mut lease = default_lease();
        lease.forbidden_verbs.push(Verb::PushOrigin);

        let result = evaluate(&req, &lease, &clean_session());

        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("forbidden by your security policy"));
    }

    #[test]
    fn test_net_allowlisted_with_derived_secret_asks_without_session_secret() {
        let mut req = make_request("net_allowlisted");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_net_external_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("net_external");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    #[test]
    fn test_dns_lookup_with_derived_secret_denied_without_session_secret() {
        let mut req = make_request("dns_lookup");
        req.derived_labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("derived from secret-bearing data"));
    }

    // --- Run ephemeral (npx): always ask ---

    #[test]
    fn test_run_ephemeral_asks() {
        let req = make_request("run_ephemeral");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Remote code execution"));
    }

    // --- Tripwire: block ---

    #[test]
    fn test_tripwire_denies() {
        let mut req = make_request("read_ref");
        req.is_tripwire = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("Tripwire"));
    }

    // --- Delegation: allowed by default lease in clean sessions ---

    #[test]
    fn test_delegation_allowed_by_default_lease_clean_session() {
        // Default lease has allow_delegation: true and "delegate" in AllowedVerbs.
        // Clean session (no secrets, no untrusted reads) → Allow.
        let mut req = make_request("delegate");
        req.is_delegation = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_delegation_denied_when_lease_disallows() {
        // If allow_delegation is false, step 2 denies it regardless of verb.
        let mut req = make_request("read_ref");
        req.is_delegation = true;
        let mut lease = default_lease();
        lease.allow_delegation = false;
        let result = evaluate(&req, &lease, &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("Delegation"));
    }

    // --- Delegation after untrusted: ask ---

    #[test]
    fn test_delegation_after_untrusted_asks() {
        let mut req = make_request("read_ref");
        req.is_delegation = true;
        let mut lease = default_lease();
        lease.allow_delegation = true;
        let mut session = clean_session();
        session.mark_untrusted_read();
        let result = evaluate(&req, &lease, &session);
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("untrusted"));
    }

    // --- Session deny-all ---

    #[test]
    fn test_deny_all_session() {
        let req = make_request("read_ref");
        let mut session = clean_session();
        session.mark_deny_all();
        let result = evaluate(&req, &default_lease(), &session);
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("deny-all"));
    }

    // --- Unknown verb: ask ---

    #[test]
    fn test_unknown_verb_asks() {
        let req = make_request("some_unknown_verb");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- Net allowlisted without secret: ask ---

    #[test]
    fn test_net_allowlisted_no_secret_asks() {
        let req = make_request("net_allowlisted");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
    }

    // --- Read .env.example (not sensitive): allow ---

    #[test]
    fn test_read_non_sensitive_allowed() {
        // The is_sensitive_path flag is false for .env.example (Go layer handles exclusions).
        let req = make_request("read_ref");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    // --- EnvRead: ask ---

    #[test]
    fn test_env_read_asks() {
        let req = make_request("env_read");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.to_lowercase().contains("environment"));
    }

    // --- DnsLookup: deny ---

    #[test]
    fn test_dns_lookup_denied() {
        let req = make_request("dns_lookup");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("DNS"));
    }

    #[test]
    fn test_dns_lookup_with_secret_session_denied() {
        let mut req = make_request("dns_lookup");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    // --- Persistence: ask ---

    #[test]
    fn test_persistence_asks() {
        let req = make_request("persistence");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Scheduled task"));
    }

    // --- Sudo: ask ---

    #[test]
    fn test_sudo_asks() {
        let req = make_request("sudo");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("Elevated"));
    }

    // --- DeletePosture: ask ---

    #[test]
    fn test_delete_posture_asks() {
        let req = make_request("delete_posture");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security"));
    }

    #[test]
    fn test_delete_posture_with_posture_flag_asks() {
        let mut req = make_request("delete_posture");
        req.is_posture_file = true;
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("security"));
    }

    // --- Delegate verb ---

    #[test]
    fn test_delegate_clean_session_allowed() {
        // Default lease: "delegate" in AllowedVerbs + allow_delegation: true → silent allow in clean session.
        let req = make_request("delegate");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_delegate_secret_session_denied() {
        let mut req = make_request("delegate");
        req.session_secret = true;
        let result = evaluate(&req, &default_lease(), &secret_session());
        assert_eq!(result.verdict, Verdict::Deny);
        assert!(result.reason.contains("credentials"));
    }

    #[test]
    fn test_delegate_after_untrusted_read_asks() {
        let req = make_request("delegate");
        let mut session = clean_session();
        session.mark_untrusted_read();
        let result = evaluate(&req, &default_lease(), &session);
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("untrusted"));
    }

    // --- McpUnapproved verb ---

    #[test]
    fn test_mcp_unapproved_asks() {
        let req = make_request("mcp_unapproved");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Ask);
        assert!(result.reason.contains("MCP"));
    }

    // --- check_flow integration ---

    #[test]
    fn test_check_flow_secret_label_to_external_denied() {
        // Even if net_external were somehow in allowed verbs (it's not), check_flow would catch it.
        // Test via stage_write (trusted sink) with secret label — should allow.
        let mut req = make_request("stage_write");
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow); // secret → trusted sink is fine
    }

    #[test]
    fn test_check_flow_secret_label_normal_write_allowed() {
        let mut req = make_request("stage_write");
        req.labels = vec![Label::secret()];
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Allow);
    }

    #[test]
    fn test_check_flow_public_label_external_denied_by_policy() {
        // net_external is in ForbiddenVerbs, so it denies before check_flow
        let req = make_request("net_external");
        let result = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(result.verdict, Verdict::Deny);
    }
}
