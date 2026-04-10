use crate::ifc;
use mister_shared::{EvalRequest, RiskTier, Verb, Verdict};

use super::policy_sinks::sink_trust_for_verb;

/// Result of policy evaluation.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub verdict: Verdict,
    pub reason: String,
    pub risk_tier: RiskTier,
}

pub(super) fn policy_result(
    verdict: Verdict,
    reason: impl Into<String>,
    risk_tier: RiskTier,
) -> PolicyResult {
    PolicyResult {
        verdict,
        reason: reason.into(),
        risk_tier,
    }
}

pub(super) fn parse_verb(req: &EvalRequest) -> Result<Verb, PolicyResult> {
    Verb::from_str(&req.verb).ok_or_else(|| {
        policy_result(
            Verdict::Ask,
            format!("Unknown verb: {}.", req.verb),
            RiskTier::R3,
        )
    })
}

pub(super) fn forbidden_verb_result(verb: Verb) -> PolicyResult {
    policy_result(
        Verdict::Deny,
        format!(
            "Verb '{}' is forbidden by your security policy.",
            verb.as_str()
        ),
        RiskTier::R4,
    )
}

pub(super) fn ask_verb_result(verb: Verb) -> PolicyResult {
    let reason = match verb {
        Verb::PushRemote => "Git push to unapproved remote requires approval.".to_string(),
        Verb::NetAllowlisted => "Network request to approved host requires approval.".to_string(),
        Verb::RunEphemeral => "Remote code execution (npx) requires approval.".to_string(),
        _ => format!("Verb '{}' requires approval.", verb.as_str()),
    };
    policy_result(Verdict::Ask, reason, RiskTier::R3)
}

pub(super) fn evaluate_allowed_verb(req: &EvalRequest, verb: Verb) -> PolicyResult {
    let sink_trust = sink_trust_for_verb(verb);
    let labels = req.effective_labels();
    let op_risk = ifc::label_floor(&labels);
    if let Err(reason) = ifc::check_flow(&labels, sink_trust, op_risk) {
        return policy_result(Verdict::Deny, reason, RiskTier::R4);
    }
    policy_result(Verdict::Allow, "Allowed by your security policy.", op_risk)
}

pub(super) fn default_unknown_verb_result(req: &EvalRequest, verb: Verb) -> PolicyResult {
    let sink_trust = sink_trust_for_verb(verb);
    let labels = req.effective_labels();
    if let Err(reason) = ifc::check_flow(&labels, sink_trust, ifc::label_floor(&labels)) {
        return policy_result(Verdict::Deny, reason, RiskTier::R4);
    }
    policy_result(
        Verdict::Ask,
        format!(
            "Verb '{}' not explicitly allowed or forbidden.",
            verb.as_str()
        ),
        RiskTier::R3,
    )
}
