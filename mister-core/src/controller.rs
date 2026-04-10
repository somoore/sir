//! Main evaluation pipeline (controller).
//!
//! Pipeline: validate intent -> check lease boundary -> check posture files
//! -> check IFC flow -> check risk tier -> generate receipt.

use crate::lease::Lease;
use crate::policy;
use crate::proof;
use crate::session::SessionState;
use mister_shared::{EvalRequest, EvalResponse};

/// Evaluate a request through the full pipeline.
///
/// The Go layer has already:
/// 1. Mapped the tool call to an intent (verb + target)
/// 2. Assigned IFC labels
/// 3. Checked posture files (set is_posture_file flag)
/// 4. Checked sensitive paths (set is_sensitive_path flag)
/// 5. Checked tripwire files (set is_tripwire flag)
/// 6. Checked delegation state (set is_delegation flag)
/// 7. Set session state flags (session_secret, session_untrusted_read)
///
/// mister-core makes the policy decision and returns the verdict.
pub fn evaluate(req: &EvalRequest, lease: &Lease, session: &SessionState) -> EvalResponse {
    // Run the policy evaluation.
    let policy_result = policy::evaluate(req, lease, session);
    let effective_labels = req.effective_labels();

    // In observe-only mode, all deny/ask verdicts become allow (but we still
    // generate the receipt with the original verdict for logging).
    let effective_verdict = if lease.observe_only {
        mister_shared::Verdict::Allow
    } else {
        policy_result.verdict
    };

    // Generate the receipt.
    proof::generate_receipt(
        effective_verdict,
        policy_result.reason,
        policy_result.risk_tier,
        effective_labels,
        &req.verb,
        &req.target,
    )
}

/// Evaluate with a JSON lease string (for when lease is passed inline).
pub fn evaluate_with_json_lease(
    req: &EvalRequest,
    lease_json: &str,
    session: &SessionState,
) -> Result<EvalResponse, String> {
    let lease = Lease::from_json(lease_json)?;
    Ok(evaluate(req, &lease, session))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mister_shared::{Label, Verdict};

    fn default_lease() -> Lease {
        Lease::default_lease()
    }

    fn clean_session() -> SessionState {
        SessionState::new()
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

    #[test]
    fn test_pipeline_normal_read() {
        let req = make_request("read_ref");
        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.verdict, Verdict::Allow);
        assert!(!resp.receipt_id.is_empty());
    }

    #[test]
    fn test_pipeline_secret_read() {
        let mut req = make_request("read_ref");
        req.is_sensitive_path = true;
        req.labels = vec![Label::secret()];
        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.verdict, Verdict::Ask);
    }

    #[test]
    fn test_pipeline_posture_write() {
        let mut req = make_request("stage_write");
        req.is_posture_file = true;
        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.verdict, Verdict::Ask);
    }

    #[test]
    fn test_pipeline_tripwire() {
        let mut req = make_request("read_ref");
        req.is_tripwire = true;
        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.verdict, Verdict::Deny);
    }

    #[test]
    fn test_pipeline_observe_only() {
        let mut lease = default_lease();
        lease.observe_only = true;

        let mut req = make_request("net_external");
        req.session_secret = true;

        let resp = evaluate(&req, &lease, &clean_session());
        // Even though net_external with secret would normally be denied,
        // observe-only mode allows everything.
        assert_eq!(resp.verdict, Verdict::Allow);
    }

    #[test]
    fn test_pipeline_secret_session_egress_blocked() {
        let mut req = make_request("net_external");
        req.session_secret = true;

        let mut session = clean_session();
        session.mark_secret();

        let resp = evaluate(&req, &default_lease(), &session);
        assert_eq!(resp.verdict, Verdict::Deny);
    }

    #[test]
    fn test_pipeline_secret_session_loopback_allowed() {
        let mut req = make_request("net_local");
        req.session_secret = true;
        req.labels = vec![Label::secret()];

        let mut session = clean_session();
        session.mark_secret();

        let resp = evaluate(&req, &default_lease(), &session);
        assert_eq!(resp.verdict, Verdict::Allow);
    }

    #[test]
    fn test_pipeline_receipt_includes_derived_labels() {
        let mut req = make_request("commit");
        req.derived_labels = vec![Label::secret()];

        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.labels_applied.len(), 1);
        assert_eq!(
            resp.labels_applied[0].sensitivity,
            mister_shared::Sensitivity::Secret
        );
    }

    #[test]
    fn test_pipeline_receipt_id_populated() {
        let req = make_request("commit");
        let resp = evaluate(&req, &default_lease(), &clean_session());
        assert_eq!(resp.receipt_id.len(), 16);
        assert!(resp.receipt_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_pipeline_deny_all_session() {
        let req = make_request("read_ref");
        let mut session = clean_session();
        session.mark_deny_all();
        let resp = evaluate(&req, &default_lease(), &session);
        assert_eq!(resp.verdict, Verdict::Deny);
    }

    #[test]
    fn test_evaluate_with_json_lease() {
        let req = make_request("read_ref");
        let session = clean_session();
        let lease_json = r#"{"lease_id":"test","mode":"guard"}"#;
        let resp = evaluate_with_json_lease(&req, lease_json, &session).unwrap();
        assert_eq!(resp.verdict, Verdict::Allow);
    }
}
