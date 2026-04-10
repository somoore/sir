// ---------------------------------------------------------------------------
// IFC Labels: RiskTier, TrustLevel, Sensitivity, Provenance, Label, Verdict
// ---------------------------------------------------------------------------

use std::fmt;

// ---------------------------------------------------------------------------
// Risk Tier
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RiskTier {
    R0, // No risk -- silent allow
    R1, // Low risk
    R2, // Moderate risk
    R3, // High risk -- approval required
    R4, // Critical risk -- deny by default
}

impl RiskTier {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<RiskTier> {
        match s {
            "R0" => Some(RiskTier::R0),
            "R1" => Some(RiskTier::R1),
            "R2" => Some(RiskTier::R2),
            "R3" => Some(RiskTier::R3),
            "R4" => Some(RiskTier::R4),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RiskTier::R0 => "R0",
            RiskTier::R1 => "R1",
            RiskTier::R2 => "R2",
            RiskTier::R3 => "R3",
            RiskTier::R4 => "R4",
        }
    }
}

impl fmt::Display for RiskTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Trust Level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustLevel {
    Trusted,          // User-owned, local workspace
    VerifiedInternal, // Agent-generated or known-good internal
    VerifiedOrigin,   // External packages with known provenance
    Untrusted,        // Unknown origin
}

impl TrustLevel {
    /// Numeric rank for ordering. Lower = more trusted.
    pub fn rank(self) -> u8 {
        match self {
            TrustLevel::Trusted => 0,
            TrustLevel::VerifiedInternal => 1,
            TrustLevel::VerifiedOrigin => 2,
            TrustLevel::Untrusted => 3,
        }
    }

    /// Return the less trusted of two levels.
    pub fn min(self, other: TrustLevel) -> TrustLevel {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<TrustLevel> {
        match s {
            "trusted" => Some(TrustLevel::Trusted),
            "verified_internal" => Some(TrustLevel::VerifiedInternal),
            "verified_origin" => Some(TrustLevel::VerifiedOrigin),
            "untrusted" => Some(TrustLevel::Untrusted),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TrustLevel::Trusted => "trusted",
            TrustLevel::VerifiedInternal => "verified_internal",
            TrustLevel::VerifiedOrigin => "verified_origin",
            TrustLevel::Untrusted => "untrusted",
        }
    }
}

impl fmt::Display for TrustLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Sensitivity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    Public,
    Internal,
    Restricted,
    Secret,
}

impl Sensitivity {
    /// Numeric rank for ordering. Higher = more sensitive.
    pub fn rank(self) -> u8 {
        match self {
            Sensitivity::Public => 0,
            Sensitivity::Internal => 1,
            Sensitivity::Restricted => 2,
            Sensitivity::Secret => 3,
        }
    }

    /// Return the more sensitive of two levels.
    pub fn max(self, other: Sensitivity) -> Sensitivity {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Sensitivity> {
        match s {
            "public" => Some(Sensitivity::Public),
            "internal" => Some(Sensitivity::Internal),
            "restricted" => Some(Sensitivity::Restricted),
            "secret" => Some(Sensitivity::Secret),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Sensitivity::Public => "public",
            Sensitivity::Internal => "internal",
            Sensitivity::Restricted => "restricted",
            Sensitivity::Secret => "secret",
        }
    }
}

impl fmt::Display for Sensitivity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provenance {
    User,
    Agent,
    ExternalPackage,
    McpTool,
    PackageInstall,
}

impl Provenance {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Provenance> {
        match s {
            "user" => Some(Provenance::User),
            "agent" => Some(Provenance::Agent),
            "external_package" => Some(Provenance::ExternalPackage),
            "mcp_tool" => Some(Provenance::McpTool),
            "package_install" => Some(Provenance::PackageInstall),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::User => "user",
            Provenance::Agent => "agent",
            Provenance::ExternalPackage => "external_package",
            Provenance::McpTool => "mcp_tool",
            Provenance::PackageInstall => "package_install",
        }
    }
}

impl fmt::Display for Provenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// IFC Label
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Label {
    pub sensitivity: Sensitivity,
    pub trust: TrustLevel,
    pub provenance: Provenance,
}

impl Label {
    pub fn new(sensitivity: Sensitivity, trust: TrustLevel, provenance: Provenance) -> Self {
        Self {
            sensitivity,
            trust,
            provenance,
        }
    }

    /// Default label for normal user-owned workspace files.
    pub fn default_user() -> Self {
        Self::new(Sensitivity::Internal, TrustLevel::Trusted, Provenance::User)
    }

    /// Label for secret files (.env, .pem, etc.).
    pub fn secret() -> Self {
        Self::new(Sensitivity::Secret, TrustLevel::Trusted, Provenance::User)
    }
}

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verdict {
    Allow,
    Deny,
    Ask,
}

impl Verdict {
    pub const ALL: [Verdict; 3] = [Verdict::Allow, Verdict::Deny, Verdict::Ask];

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Verdict> {
        match s {
            "allow" => Some(Verdict::Allow),
            "deny" => Some(Verdict::Deny),
            "ask" => Some(Verdict::Ask),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Ask => "ask",
        }
    }
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_risk_tier_ordering() {
        assert!(RiskTier::R0 < RiskTier::R1);
        assert!(RiskTier::R1 < RiskTier::R2);
        assert!(RiskTier::R2 < RiskTier::R3);
        assert!(RiskTier::R3 < RiskTier::R4);
    }

    #[test]
    fn test_trust_level_min() {
        assert_eq!(
            TrustLevel::Trusted.min(TrustLevel::Untrusted),
            TrustLevel::Untrusted
        );
        assert_eq!(
            TrustLevel::Untrusted.min(TrustLevel::Trusted),
            TrustLevel::Untrusted
        );
        assert_eq!(
            TrustLevel::VerifiedInternal.min(TrustLevel::VerifiedOrigin),
            TrustLevel::VerifiedOrigin
        );
    }

    #[test]
    fn test_sensitivity_max() {
        assert_eq!(
            Sensitivity::Public.max(Sensitivity::Secret),
            Sensitivity::Secret
        );
        assert_eq!(
            Sensitivity::Secret.max(Sensitivity::Public),
            Sensitivity::Secret
        );
        assert_eq!(
            Sensitivity::Internal.max(Sensitivity::Restricted),
            Sensitivity::Restricted
        );
    }
}
