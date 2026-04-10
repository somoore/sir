use crate::lease::Lease;
use crate::session::SessionState;
use mister_shared::{EvalRequest, RiskTier, Verb, Verdict};

use super::policy_common::{policy_result, PolicyResult};

pub(super) fn evaluate_session_preconditions(
    req: &EvalRequest,
    lease: &Lease,
    session: &SessionState,
) -> Option<PolicyResult> {
    if session.deny_all {
        return Some(policy_result(
            Verdict::Deny,
            "Session in deny-all state: security settings were modified unexpectedly.",
            RiskTier::R4,
        ));
    }
    if req.is_tripwire {
        return Some(policy_result(
            Verdict::Deny,
            "Tripwire file accessed.",
            RiskTier::R4,
        ));
    }
    if req.is_delegation {
        if !lease.allow_delegation {
            return Some(policy_result(
                Verdict::Deny,
                "Delegation not allowed by your security policy.",
                RiskTier::R4,
            ));
        }
        if session.recently_read_untrusted {
            return Some(policy_result(
                Verdict::Ask,
                "Delegation after untrusted data read.",
                RiskTier::R3,
            ));
        }
    }
    None
}

pub(super) fn evaluate_preapproval_guards(req: &EvalRequest, verb: Verb) -> Option<PolicyResult> {
    if req.is_posture_file && matches!(verb, Verb::StageWrite | Verb::DeletePosture) {
        let reason = if matches!(verb, Verb::DeletePosture) {
            "Delete/link of security settings file requires approval."
        } else {
            "Write to security settings file requires approval."
        };
        return Some(policy_result(Verdict::Ask, reason, RiskTier::R3));
    }
    if matches!(verb, Verb::DeletePosture) {
        return Some(policy_result(
            Verdict::Ask,
            "Delete/link targeting security-relevant file requires approval.",
            RiskTier::R3,
        ));
    }
    if req.is_sensitive_path && matches!(verb, Verb::ReadRef) {
        return Some(policy_result(
            Verdict::Ask,
            "Read of sensitive file requires approval.",
            RiskTier::R3,
        ));
    }
    match verb {
        Verb::EnvRead => Some(policy_result(
            Verdict::Ask,
            "Environment variable read may expose secrets.",
            RiskTier::R3,
        )),
        Verb::Persistence => Some(policy_result(
            Verdict::Ask,
            "Scheduled task creation requires approval.",
            RiskTier::R3,
        )),
        Verb::Sudo => Some(policy_result(
            Verdict::Ask,
            "Elevated privilege execution requires approval.",
            RiskTier::R3,
        )),
        Verb::SirSelf => Some(policy_result(
            Verdict::Ask,
            "sir CLI self-modification requires developer approval.",
            RiskTier::R3,
        )),
        Verb::McpUnapproved => Some(policy_result(
            Verdict::Ask,
            "MCP server not in approved list — unknown server.",
            RiskTier::R3,
        )),
        _ => None,
    }
}

pub(super) fn evaluate_network_guardrails(req: &EvalRequest, verb: Verb) -> Option<PolicyResult> {
    match verb {
        Verb::DnsLookup => {
            if req.session_secret {
                Some(policy_result(
                    Verdict::Deny,
                    "DNS lookup blocked — your session contains credentials.",
                    RiskTier::R4,
                ))
            } else {
                Some(policy_result(
                    Verdict::Deny,
                    "DNS lookup (outbound request) not allowed by default.",
                    RiskTier::R4,
                ))
            }
        }
        Verb::NetExternal => {
            if req.session_secret {
                Some(policy_result(
                    Verdict::Deny,
                    "Network requests blocked — your session contains credentials.",
                    RiskTier::R4,
                ))
            } else {
                Some(policy_result(
                    Verdict::Deny,
                    "Network requests to external hosts are blocked by default.",
                    RiskTier::R4,
                ))
            }
        }
        _ => None,
    }
}

pub(super) fn evaluate_secret_session_guards(
    req: &EvalRequest,
    _session: &SessionState,
    verb: Verb,
) -> Option<PolicyResult> {
    if !req.session_secret {
        return None;
    }
    match verb {
        Verb::NetExternal => Some(policy_result(
            Verdict::Deny,
            "session carries secret data; external network egress blocked",
            RiskTier::R4,
        )),
        Verb::PushOrigin => Some(policy_result(
            Verdict::Ask,
            "Git push to approved remote while session contains credentials.",
            RiskTier::R3,
        )),
        Verb::PushRemote => Some(policy_result(
            Verdict::Deny,
            "Git push to unapproved remote blocked — your session contains credentials.",
            RiskTier::R4,
        )),
        Verb::NetLocal => Some(policy_result(
            Verdict::Allow,
            "Loopback network access allowed.",
            RiskTier::R0,
        )),
        Verb::NetAllowlisted => Some(policy_result(
            Verdict::Allow,
            "Approved host network access allowed.",
            RiskTier::R1,
        )),
        _ => None,
    }
}

pub(super) fn evaluate_delegation_guardrails(
    req: &EvalRequest,
    lease: &Lease,
    session: &SessionState,
    verb: Verb,
) -> Option<PolicyResult> {
    if !matches!(verb, Verb::Delegate) {
        return None;
    }
    if req.session_secret {
        return Some(policy_result(
            Verdict::Deny,
            "Delegation blocked — your session contains credentials.",
            RiskTier::R4,
        ));
    }
    if session.recently_read_untrusted {
        return Some(policy_result(
            Verdict::Ask,
            "Delegation after untrusted content was read.",
            RiskTier::R3,
        ));
    }
    if !lease.is_verb_allowed(verb) && !lease.is_verb_ask(verb) && !lease.is_verb_forbidden(verb) {
        return Some(policy_result(
            Verdict::Ask,
            "Agent delegation requires approval.",
            RiskTier::R3,
        ));
    }
    None
}
