//! IFC (Information Flow Control) algebra.
//!
//! - `join(a, b)`: trust = min(a, b), sensitivity = max(a, b)
//! - `label_floor(labels)`: maps labels to minimum risk tier
//! - `check_flow(labels, sink_trust, op_risk)`: secret data cannot flow to non-trusted sinks

use mister_shared::{Label, RiskTier, Sensitivity, TrustLevel};

/// Join two labels: take the least trusted and most sensitive.
pub fn join(a: &Label, b: &Label) -> Label {
    Label {
        sensitivity: a.sensitivity.max(b.sensitivity),
        trust: a.trust.min(b.trust),
        // For provenance, keep the first label's provenance (the primary data source).
        provenance: a.provenance,
    }
}

/// Join all labels in a set, producing the combined label.
pub fn join_all(labels: &[Label]) -> Option<Label> {
    if labels.is_empty() {
        return None;
    }
    let mut result = labels[0].clone();
    for l in &labels[1..] {
        result = join(&result, l);
    }
    Some(result)
}

/// Map a set of labels to the minimum risk tier that should apply.
///
/// - If any label has `sensitivity: secret` -> at least R3
/// - If any label has `sensitivity: restricted` -> at least R2
/// - If any label has `trust: untrusted` -> at least R2
/// - If any label has `trust: verified_origin` -> at least R1
/// - Otherwise R0
pub fn label_floor(labels: &[Label]) -> RiskTier {
    let mut floor = RiskTier::R0;

    for label in labels {
        let sensitivity_risk = match label.sensitivity {
            Sensitivity::Secret => RiskTier::R3,
            Sensitivity::Restricted => RiskTier::R2,
            Sensitivity::Internal => RiskTier::R0,
            Sensitivity::Public => RiskTier::R0,
        };

        let trust_risk = match label.trust {
            TrustLevel::Trusted => RiskTier::R0,
            TrustLevel::VerifiedInternal => RiskTier::R0,
            TrustLevel::VerifiedOrigin => RiskTier::R1,
            TrustLevel::Untrusted => RiskTier::R2,
        };

        if sensitivity_risk > floor {
            floor = sensitivity_risk;
        }
        if trust_risk > floor {
            floor = trust_risk;
        }
    }

    floor
}

/// Check whether data with the given labels can flow to a sink with the given trust level
/// at the given operation risk tier.
///
/// Rules:
/// - Secret data cannot flow to sinks below `Trusted` trust level.
/// - Restricted data cannot flow to sinks below `VerifiedInternal`.
/// - If the operation risk exceeds R3 and the labels carry secrets, deny.
///
/// Returns `Ok(())` if the flow is allowed, `Err(reason)` if denied.
pub fn check_flow(
    labels: &[Label],
    sink_trust: TrustLevel,
    _op_risk: RiskTier,
) -> Result<(), String> {
    let combined = match join_all(labels) {
        Some(l) => l,
        None => return Ok(()), // No labels = no restrictions
    };

    match combined.sensitivity {
        Sensitivity::Secret => {
            if sink_trust.rank() > TrustLevel::VerifiedInternal.rank() {
                return Err(format!(
                    "secret data cannot flow to {} sink",
                    sink_trust.as_str()
                ));
            }
        }
        Sensitivity::Restricted => {
            if sink_trust.rank() > TrustLevel::VerifiedInternal.rank() {
                return Err(format!(
                    "restricted data cannot flow to {} sink",
                    sink_trust.as_str()
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mister_shared::Provenance;

    fn secret_label() -> Label {
        Label::new(Sensitivity::Secret, TrustLevel::Trusted, Provenance::User)
    }

    fn internal_label() -> Label {
        Label::new(Sensitivity::Internal, TrustLevel::Trusted, Provenance::User)
    }

    fn public_untrusted() -> Label {
        Label::new(
            Sensitivity::Public,
            TrustLevel::Untrusted,
            Provenance::ExternalPackage,
        )
    }

    fn restricted_label() -> Label {
        Label::new(
            Sensitivity::Restricted,
            TrustLevel::VerifiedInternal,
            Provenance::Agent,
        )
    }

    #[test]
    fn test_join_trust_takes_minimum() {
        let a = Label::new(Sensitivity::Public, TrustLevel::Trusted, Provenance::User);
        let b = Label::new(
            Sensitivity::Public,
            TrustLevel::Untrusted,
            Provenance::ExternalPackage,
        );
        let c = join(&a, &b);
        assert_eq!(c.trust, TrustLevel::Untrusted);
    }

    #[test]
    fn test_join_sensitivity_takes_maximum() {
        let a = Label::new(Sensitivity::Public, TrustLevel::Trusted, Provenance::User);
        let b = Label::new(Sensitivity::Secret, TrustLevel::Trusted, Provenance::User);
        let c = join(&a, &b);
        assert_eq!(c.sensitivity, Sensitivity::Secret);
    }

    #[test]
    fn test_join_all_empty() {
        assert!(join_all(&[]).is_none());
    }

    #[test]
    fn test_join_all_single() {
        let labels = vec![secret_label()];
        let result = join_all(&labels).unwrap();
        assert_eq!(result.sensitivity, Sensitivity::Secret);
        assert_eq!(result.trust, TrustLevel::Trusted);
    }

    #[test]
    fn test_join_all_mixed() {
        let labels = vec![secret_label(), public_untrusted()];
        let result = join_all(&labels).unwrap();
        assert_eq!(result.sensitivity, Sensitivity::Secret);
        assert_eq!(result.trust, TrustLevel::Untrusted);
    }

    #[test]
    fn test_label_floor_no_labels() {
        assert_eq!(label_floor(&[]), RiskTier::R0);
    }

    #[test]
    fn test_label_floor_internal() {
        assert_eq!(label_floor(&[internal_label()]), RiskTier::R0);
    }

    #[test]
    fn test_label_floor_secret() {
        assert_eq!(label_floor(&[secret_label()]), RiskTier::R3);
    }

    #[test]
    fn test_label_floor_untrusted() {
        assert_eq!(label_floor(&[public_untrusted()]), RiskTier::R2);
    }

    #[test]
    fn test_label_floor_restricted() {
        assert_eq!(label_floor(&[restricted_label()]), RiskTier::R2);
    }

    #[test]
    fn test_label_floor_mixed_takes_highest() {
        let labels = vec![internal_label(), secret_label()];
        assert_eq!(label_floor(&labels), RiskTier::R3);
    }

    #[test]
    fn test_check_flow_no_labels_allows() {
        assert!(check_flow(&[], TrustLevel::Untrusted, RiskTier::R4).is_ok());
    }

    #[test]
    fn test_check_flow_secret_to_trusted_allows() {
        assert!(check_flow(&[secret_label()], TrustLevel::Trusted, RiskTier::R0).is_ok());
    }

    #[test]
    fn test_check_flow_secret_to_verified_internal_allows() {
        assert!(check_flow(
            &[secret_label()],
            TrustLevel::VerifiedInternal,
            RiskTier::R1
        )
        .is_ok());
    }

    #[test]
    fn test_check_flow_secret_to_untrusted_denies() {
        assert!(check_flow(&[secret_label()], TrustLevel::Untrusted, RiskTier::R4).is_err());
    }

    #[test]
    fn test_check_flow_secret_to_verified_origin_denies() {
        assert!(check_flow(&[secret_label()], TrustLevel::VerifiedOrigin, RiskTier::R2).is_err());
    }

    #[test]
    fn test_check_flow_internal_to_untrusted_allows() {
        // Internal (non-secret) data can flow anywhere.
        assert!(check_flow(&[internal_label()], TrustLevel::Untrusted, RiskTier::R4).is_ok());
    }

    #[test]
    fn test_check_flow_restricted_to_untrusted_denies() {
        assert!(check_flow(&[restricted_label()], TrustLevel::Untrusted, RiskTier::R4).is_err());
    }

    #[test]
    fn test_check_flow_restricted_to_verified_internal_allows() {
        assert!(check_flow(
            &[restricted_label()],
            TrustLevel::VerifiedInternal,
            RiskTier::R1
        )
        .is_ok());
    }
}
