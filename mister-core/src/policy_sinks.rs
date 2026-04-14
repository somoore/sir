use mister_shared::{EvalRequest, TrustLevel, Verb, Verdict};

use super::policy_common::PolicyResult;

pub(super) fn evaluate_derived_secret_sink(req: &EvalRequest, verb: Verb) -> Option<PolicyResult> {
    if !req.has_derived_secret() {
        return None;
    }

    let result = match verb {
        Verb::StageWrite => PolicyResult {
            verdict: Verdict::Ask,
            reason: "Write derived from secret-bearing data requires approval.".to_string(),
            risk_tier: mister_shared::RiskTier::R3,
        },
        Verb::Commit => PolicyResult {
            verdict: Verdict::Ask,
            reason: "Git commit includes content derived from secret-bearing data.".to_string(),
            risk_tier: mister_shared::RiskTier::R3,
        },
        Verb::PushOrigin => PolicyResult {
            verdict: Verdict::Ask,
            reason: "Git push to approved remote includes content derived from secret-bearing data."
                .to_string(),
            risk_tier: mister_shared::RiskTier::R3,
        },
        Verb::PushRemote => PolicyResult {
            verdict: Verdict::Deny,
            reason:
                "Git push to unapproved remote blocked — staged content derives from secret-bearing data."
                    .to_string(),
            risk_tier: mister_shared::RiskTier::R4,
        },
        Verb::NetAllowlisted => PolicyResult {
            verdict: Verdict::Ask,
            reason:
                "Network request to approved host carries content derived from secret-bearing data."
                    .to_string(),
            risk_tier: mister_shared::RiskTier::R3,
        },
        Verb::NetExternal => PolicyResult {
            verdict: Verdict::Deny,
            reason:
                "External network egress blocked — request carries content derived from secret-bearing data."
                    .to_string(),
            risk_tier: mister_shared::RiskTier::R4,
        },
        Verb::DnsLookup => PolicyResult {
            verdict: Verdict::Deny,
            reason:
                "DNS lookup blocked — request carries content derived from secret-bearing data."
                    .to_string(),
            risk_tier: mister_shared::RiskTier::R4,
        },
        _ => return None,
    };

    Some(result)
}

/// Map a verb to the trust level of its sink.
/// Used by check_flow to determine if secret data can flow to this destination.
pub(super) fn sink_trust_for_verb(verb: Verb) -> TrustLevel {
    match verb {
        Verb::NetLocal => TrustLevel::VerifiedInternal,
        Verb::NetAllowlisted => TrustLevel::VerifiedInternal,
        Verb::NetExternal => TrustLevel::Untrusted,
        Verb::PushOrigin => TrustLevel::VerifiedInternal,
        Verb::PushRemote => TrustLevel::Untrusted,
        Verb::StageWrite => TrustLevel::Trusted,
        Verb::Commit => TrustLevel::Trusted,
        Verb::ExecuteDryRun => TrustLevel::Trusted,
        Verb::RunTests => TrustLevel::Trusted,
        Verb::ReadRef => TrustLevel::Trusted,
        Verb::ListFiles => TrustLevel::Trusted,
        Verb::SearchCode => TrustLevel::Trusted,
        Verb::DnsLookup => TrustLevel::Untrusted,
        Verb::RunEphemeral => TrustLevel::Untrusted,
        Verb::Persistence
        | Verb::Sudo
        | Verb::DeletePosture
        | Verb::Delegate
        | Verb::EnvRead
        | Verb::CredentialDetected
        | Verb::ElicitationHarvest => TrustLevel::Trusted,
        Verb::McpUnapproved => TrustLevel::Untrusted,
        Verb::McpNetworkUnapproved => TrustLevel::Untrusted,
        Verb::McpOnboarding => TrustLevel::Trusted,
        Verb::McpBinaryDrift => TrustLevel::Untrusted,
        Verb::McpCredentialLeak | Verb::McpInjectionDetected => TrustLevel::Untrusted,
        Verb::SirSelf => TrustLevel::Trusted,
    }
}
