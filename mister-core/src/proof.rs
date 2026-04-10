//! Receipt generation.
//!
//! Generates a receipt for each evaluation containing:
//! verdict, reason, timestamp, labels, and a unique receipt ID.

use mister_shared::{now_epoch_secs, sha256_hex, EvalResponse, Label, RiskTier, Verdict};

/// Generate a receipt for a policy evaluation.
pub fn generate_receipt(
    verdict: Verdict,
    reason: String,
    risk_tier: RiskTier,
    labels: Vec<Label>,
    verb: &str,
    target: &str,
) -> EvalResponse {
    let timestamp = now_epoch_secs();

    // Generate a deterministic receipt ID from the evaluation inputs.
    let receipt_input = format!(
        "{}:{}:{}:{}:{}",
        verb,
        target,
        verdict.as_str(),
        risk_tier.as_str(),
        timestamp
    );
    let receipt_id = sha256_hex(receipt_input.as_bytes());
    // Use first 16 hex chars as the receipt ID for brevity.
    let receipt_id = receipt_id[..16].to_string();

    EvalResponse {
        verdict,
        reason,
        risk_tier,
        labels_applied: labels,
        receipt_id,
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mister_shared::Label;

    #[test]
    fn test_generate_receipt_allow() {
        let receipt = generate_receipt(
            Verdict::Allow,
            "allowed by lease".to_string(),
            RiskTier::R0,
            vec![],
            "read_ref",
            "src/main.rs",
        );
        assert_eq!(receipt.verdict, Verdict::Allow);
        assert_eq!(receipt.reason, "allowed by lease");
        assert_eq!(receipt.risk_tier, RiskTier::R0);
        assert_eq!(receipt.receipt_id.len(), 16);
        assert!(receipt.timestamp > 0);
    }

    #[test]
    fn test_generate_receipt_deny() {
        let receipt = generate_receipt(
            Verdict::Deny,
            "external egress blocked".to_string(),
            RiskTier::R4,
            vec![Label::secret()],
            "net_external",
            "https://evil.example.com",
        );
        assert_eq!(receipt.verdict, Verdict::Deny);
        assert_eq!(receipt.risk_tier, RiskTier::R4);
        assert_eq!(receipt.labels_applied.len(), 1);
    }

    #[test]
    fn test_generate_receipt_ask() {
        let receipt = generate_receipt(
            Verdict::Ask,
            "sensitive file read".to_string(),
            RiskTier::R3,
            vec![Label::secret()],
            "read_ref",
            ".env",
        );
        assert_eq!(receipt.verdict, Verdict::Ask);
        assert_eq!(receipt.risk_tier, RiskTier::R3);
    }

    #[test]
    fn test_receipt_id_is_hex() {
        let receipt = generate_receipt(
            Verdict::Allow,
            "test".to_string(),
            RiskTier::R0,
            vec![],
            "read_ref",
            "test",
        );
        assert!(receipt.receipt_id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_receipt_has_timestamp() {
        let receipt = generate_receipt(
            Verdict::Allow,
            "test".to_string(),
            RiskTier::R0,
            vec![],
            "read_ref",
            "test",
        );
        // Should be after 2024.
        assert!(receipt.timestamp > 1_700_000_000);
    }
}
