use std::fmt;

pub const SESSION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PostureState {
    Normal,
    Elevated,
    Critical,
}

impl PostureState {
    pub const ALL: [PostureState; 3] = [
        PostureState::Normal,
        PostureState::Elevated,
        PostureState::Critical,
    ];

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<PostureState> {
        match s {
            "normal" => Some(PostureState::Normal),
            "elevated" => Some(PostureState::Elevated),
            "critical" => Some(PostureState::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PostureState::Normal => "normal",
            PostureState::Elevated => "elevated",
            PostureState::Critical => "critical",
        }
    }

    pub fn rank(self) -> u8 {
        match self {
            PostureState::Normal => 1,
            PostureState::Elevated => 2,
            PostureState::Critical => 3,
        }
    }
}

impl fmt::Display for PostureState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ApprovalScope {
    Session,
    Turn,
}

impl ApprovalScope {
    pub const ALL: [ApprovalScope; 2] = [ApprovalScope::Session, ApprovalScope::Turn];

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<ApprovalScope> {
        match s {
            "session" => Some(ApprovalScope::Session),
            "turn" => Some(ApprovalScope::Turn),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalScope::Session => "session",
            ApprovalScope::Turn => "turn",
        }
    }
}

impl fmt::Display for ApprovalScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_json, JsonValue, Verb, Verdict};

    fn array_values(doc: &JsonValue, key: &str) -> Vec<String> {
        doc.get(key)
            .and_then(|v| v.as_array())
            .unwrap_or(&[])
            .iter()
            .filter_map(|item| item.get("wire").and_then(|v| v.as_str()))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn test_policy_surface_matches_shared_spec() {
        let spec = parse_json(include_str!("../policy_surface.json")).unwrap();

        assert_eq!(
            spec.get("session_schema_version")
                .and_then(|v| match v {
                    JsonValue::Number(n) if *n >= 0.0 => Some(*n as u64),
                    _ => None,
                })
                .expect("session_schema_version must be numeric"),
            SESSION_SCHEMA_VERSION as u64
        );

        let verb_wires: Vec<String> = Verb::ALL.iter().map(|v| v.as_str().to_string()).collect();
        assert_eq!(array_values(&spec, "verbs"), verb_wires);

        let verdict_wires: Vec<String> = Verdict::ALL
            .iter()
            .map(|v| v.as_str().to_string())
            .collect();
        assert_eq!(array_values(&spec, "verdicts"), verdict_wires);

        let posture_wires: Vec<String> = PostureState::ALL
            .iter()
            .map(|v| v.as_str().to_string())
            .collect();
        assert_eq!(array_values(&spec, "posture_states"), posture_wires);

        let scope_wires: Vec<String> = ApprovalScope::ALL
            .iter()
            .map(|v| v.as_str().to_string())
            .collect();
        assert_eq!(array_values(&spec, "approval_scopes"), scope_wires);
    }
}
