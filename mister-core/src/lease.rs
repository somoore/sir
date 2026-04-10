//! Lease model and boundary checks.
//!
//! The lease defines the agent's granted authority. Everything outside
//! the lease is denied by default.

use mister_shared::{parse_json, JsonValue, RiskTier, Sink, TrustLevel, Verb};

/// The lease configuration.
#[derive(Debug, Clone)]
pub struct Lease {
    pub lease_id: String,
    pub issuer: String,
    pub principal: String,
    pub mission: String,
    pub mode: String,
    pub compiler_ceiling: RiskTier,

    pub sensitive_paths: Vec<String>,
    pub sensitive_path_exclusions: Vec<String>,
    pub posture_files: Vec<String>,
    pub sentinel_files_for_installs: Vec<String>,

    pub allowed_verbs: Vec<Verb>,
    pub forbidden_verbs: Vec<Verb>,
    pub ask_verbs: Vec<Verb>,

    pub approved_remotes: Vec<String>,
    pub approved_hosts: Vec<String>,

    pub sinks: Vec<Sink>,

    pub approval_risk: RiskTier,
    pub allow_delegation: bool,
    pub observe_only: bool,
}

impl Lease {
    /// Create the default lease as specified in the plan.
    pub fn default_lease() -> Self {
        Self {
            lease_id: "default".to_string(),
            issuer: "sir".to_string(),
            principal: "user".to_string(),
            mission: "coding task with secret access control and posture protection".to_string(),
            mode: "guard".to_string(),
            compiler_ceiling: RiskTier::R3,

            sensitive_paths: vec![
                ".env".into(),
                ".env.local".into(),
                ".env.production".into(),
                ".env.development".into(),
                "*.pem".into(),
                "*.key".into(),
                ".aws/*".into(),
                ".ssh/*".into(),
                ".netrc".into(),
                ".npmrc".into(),
                "credentials.json".into(),
                "secrets.*".into(),
                ".docker/config.json".into(),
                ".kube/config".into(),
                ".git-credentials".into(),
                ".pypirc".into(),
                ".terraform/credentials.tfrc.json".into(),
                ".gradle/gradle.properties".into(),
                ".config/gh/hosts.yml".into(),
            ],

            sensitive_path_exclusions: vec![
                ".env.example".into(),
                ".env.sample".into(),
                ".env.template".into(),
                "testdata/**".into(),
                "fixtures/**".into(),
                "test/**/*.pem".into(),
                "test/**/*.key".into(),
            ],

            posture_files: vec![
                ".claude/hooks/hooks.json".into(),
                ".claude/settings.json".into(),
                "CLAUDE.md".into(),
                ".mcp.json".into(),
                ".claude/.sir/lease.json".into(),
            ],

            sentinel_files_for_installs: vec![
                ".claude/hooks/hooks.json".into(),
                ".claude/settings.json".into(),
                "CLAUDE.md".into(),
                ".env".into(),
                ".mcp.json".into(),
            ],

            allowed_verbs: vec![
                Verb::ReadRef,
                Verb::StageWrite,
                Verb::ExecuteDryRun,
                Verb::RunTests,
                Verb::ListFiles,
                Verb::SearchCode,
                Verb::Commit,
                Verb::NetLocal,
                Verb::PushOrigin,
                Verb::Delegate, // Agent tool: allowed in clean sessions; policy still blocks if secret/untrusted
            ],

            forbidden_verbs: vec![Verb::NetExternal],

            ask_verbs: vec![Verb::PushRemote, Verb::NetAllowlisted, Verb::RunEphemeral],

            approved_remotes: vec!["origin".into()],
            approved_hosts: vec![
                "localhost".into(),
                "127.0.0.1".into(),
                "::1".into(),
                "host.docker.internal".into(),
            ],

            sinks: vec![
                Sink {
                    pattern: "file://**".into(),
                    trust: TrustLevel::Trusted,
                    min_risk: RiskTier::R0,
                },
                Sink {
                    pattern: "shell://workspace".into(),
                    trust: TrustLevel::Trusted,
                    min_risk: RiskTier::R0,
                },
                Sink {
                    pattern: "git-commit".into(),
                    trust: TrustLevel::Trusted,
                    min_risk: RiskTier::R0,
                },
                Sink {
                    pattern: "git-push-approved".into(),
                    trust: TrustLevel::VerifiedInternal,
                    min_risk: RiskTier::R2,
                },
                Sink {
                    pattern: "git-push-unapproved".into(),
                    trust: TrustLevel::Untrusted,
                    min_risk: RiskTier::R4,
                },
                Sink {
                    pattern: "net://approved".into(),
                    trust: TrustLevel::VerifiedInternal,
                    min_risk: RiskTier::R1,
                },
                Sink {
                    pattern: "net://loopback".into(),
                    trust: TrustLevel::VerifiedInternal,
                    min_risk: RiskTier::R0,
                },
                Sink {
                    pattern: "net://external".into(),
                    trust: TrustLevel::Untrusted,
                    min_risk: RiskTier::R4,
                },
                Sink {
                    pattern: "*".into(),
                    trust: TrustLevel::Untrusted,
                    min_risk: RiskTier::R4,
                },
            ],

            approval_risk: RiskTier::R3,
            allow_delegation: true,
            observe_only: false,
        }
    }

    /// Parse a lease from a JSON string.
    pub fn from_json(s: &str) -> Result<Self, String> {
        let val = parse_json(s)?;
        let mut lease = Self::default_lease();

        if let Some(v) = val.get("lease_id").and_then(|v| v.as_str()) {
            lease.lease_id = v.to_string();
        }
        if let Some(v) = val.get("issuer").and_then(|v| v.as_str()) {
            lease.issuer = v.to_string();
        }
        if let Some(v) = val.get("principal").and_then(|v| v.as_str()) {
            lease.principal = v.to_string();
        }
        if let Some(v) = val.get("mission").and_then(|v| v.as_str()) {
            lease.mission = v.to_string();
        }
        if let Some(v) = val.get("mode").and_then(|v| v.as_str()) {
            lease.mode = v.to_string();
        }
        if let Some(v) = val
            .get("compiler_ceiling")
            .and_then(|v| v.as_str())
            .and_then(RiskTier::from_str)
        {
            lease.compiler_ceiling = v;
        }
        if let Some(v) = val
            .get("approval_risk")
            .and_then(|v| v.as_str())
            .and_then(RiskTier::from_str)
        {
            lease.approval_risk = v;
        }
        if let Some(v) = val.get("allow_delegation").and_then(|v| v.as_bool()) {
            lease.allow_delegation = v;
        }
        if let Some(v) = val.get("observe_only").and_then(|v| v.as_bool()) {
            lease.observe_only = v;
        }

        if let Some(arr) = val.get("sensitive_paths").and_then(|v| v.as_array()) {
            lease.sensitive_paths = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = val
            .get("sensitive_path_exclusions")
            .and_then(|v| v.as_array())
        {
            lease.sensitive_path_exclusions = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = val.get("posture_files").and_then(|v| v.as_array()) {
            lease.posture_files = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = val
            .get("sentinel_files_for_installs")
            .and_then(|v| v.as_array())
        {
            lease.sentinel_files_for_installs = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = val.get("approved_remotes").and_then(|v| v.as_array()) {
            lease.approved_remotes = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = val.get("approved_hosts").and_then(|v| v.as_array()) {
            lease.approved_hosts = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }

        if let Some(arr) = val.get("allowed_verbs").and_then(|v| v.as_array()) {
            lease.allowed_verbs = arr
                .iter()
                .filter_map(|v| v.as_str().and_then(Verb::from_str))
                .collect();
        }
        if let Some(arr) = val.get("forbidden_verbs").and_then(|v| v.as_array()) {
            lease.forbidden_verbs = arr
                .iter()
                .filter_map(|v| v.as_str().and_then(Verb::from_str))
                .collect();
        }
        if let Some(arr) = val.get("ask_verbs").and_then(|v| v.as_array()) {
            lease.ask_verbs = arr
                .iter()
                .filter_map(|v| v.as_str().and_then(Verb::from_str))
                .collect();
        }

        if let Some(arr) = val.get("sinks").and_then(|v| v.as_array()) {
            lease.sinks = arr.iter().filter_map(parse_sink).collect();
        }

        Ok(lease)
    }

    /// Check if a verb is explicitly allowed by the lease.
    pub fn is_verb_allowed(&self, verb: Verb) -> bool {
        self.allowed_verbs.contains(&verb)
    }

    /// Check if a verb is explicitly forbidden by the lease.
    pub fn is_verb_forbidden(&self, verb: Verb) -> bool {
        self.forbidden_verbs.contains(&verb)
    }

    /// Check if a verb requires asking the user.
    pub fn is_verb_ask(&self, verb: Verb) -> bool {
        self.ask_verbs.contains(&verb)
    }

    /// Get the sink definition for a given verb/pattern.
    pub fn sink_for_verb(&self, verb: Verb) -> Option<&Sink> {
        let pattern = match verb {
            Verb::NetLocal => "net://loopback",
            Verb::NetAllowlisted => "net://approved",
            Verb::NetExternal | Verb::DnsLookup => "net://external",
            Verb::PushOrigin => "git-push-approved",
            Verb::PushRemote => "git-push-unapproved",
            Verb::StageWrite | Verb::DeletePosture => "file://**",
            Verb::Commit => "git-commit",
            Verb::ExecuteDryRun
            | Verb::RunTests
            | Verb::EnvRead
            | Verb::Persistence
            | Verb::Sudo => "shell://workspace",
            Verb::RunEphemeral => "*",
            _ => return None,
        };

        self.sinks.iter().find(|s| s.pattern == pattern)
    }

    /// Check whether a path should be excluded from sensitive path matching.
    /// Exclusions are checked BEFORE sensitive path matches.
    ///
    /// In addition to the configured exclusions, any path ending in
    /// `.example`, `.sample`, or `.template` is automatically excluded.
    pub fn is_path_excluded(&self, path: &str) -> bool {
        // Check suffix-based exclusions first
        let suffixes = [".example", ".sample", ".template"];
        for suffix in &suffixes {
            if path.ends_with(suffix) {
                return true;
            }
        }

        // Check configured exclusions
        for exclusion in &self.sensitive_path_exclusions {
            if glob_match(exclusion, path) {
                return true;
            }
        }

        false
    }

    /// Check whether a path matches any sensitive path pattern,
    /// after first checking exclusions.
    pub fn is_sensitive_path(&self, path: &str) -> bool {
        // Check exclusions BEFORE sensitive path matches
        if self.is_path_excluded(path) {
            return false;
        }

        for pattern in &self.sensitive_paths {
            if glob_match(pattern, path) {
                return true;
            }
        }

        false
    }
}

/// Simple glob matching for path patterns.
/// Supports:
/// - `*` matches any sequence of non-`/` characters
/// - `**` matches any sequence of characters including `/`
/// - Literal matching otherwise
fn glob_match(pattern: &str, path: &str) -> bool {
    // Handle ** (recursive glob)
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.splitn(2, "**").collect();
        if parts.len() == 2 {
            let prefix = parts[0].trim_end_matches('/');
            let suffix = parts[1].trim_start_matches('/');

            // Path must start with prefix (if non-empty)
            if !prefix.is_empty() && !path.starts_with(prefix) {
                return false;
            }

            // If suffix is empty, prefix match is enough
            if suffix.is_empty() {
                return true;
            }

            // Check if any suffix of path matches the suffix pattern
            let start = if prefix.is_empty() { 0 } else { prefix.len() };
            for i in start..=path.len() {
                if glob_match(suffix, &path[i..]) {
                    return true;
                }
            }
            return false;
        }
    }

    // Handle single * (non-recursive)
    if pattern.contains('*') && !pattern.contains("**") {
        let parts: Vec<&str> = pattern.splitn(2, '*').collect();
        if parts.len() == 2 {
            let prefix = parts[0];
            let suffix = parts[1];

            if !path.starts_with(prefix) {
                return false;
            }

            let rest = &path[prefix.len()..];

            if suffix.is_empty() {
                // * at end: match anything without /
                return !rest.contains('/');
            }

            // Find suffix in rest (without crossing /)
            if let Some(pos) = rest.find(suffix) {
                let between = &rest[..pos];
                return !between.contains('/');
            }
            return false;
        }
    }

    // Literal match
    pattern == path
}

fn parse_sink(val: &JsonValue) -> Option<Sink> {
    let pattern = val.get("pattern")?.as_str()?.to_string();
    let trust = val
        .get("trust")
        .and_then(|v| v.as_str())
        .and_then(TrustLevel::from_str)?;
    let min_risk = val
        .get("min_risk")
        .and_then(|v| v.as_str())
        .and_then(RiskTier::from_str)?;
    Some(Sink {
        pattern,
        trust,
        min_risk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_lease_allowed_verbs() {
        let lease = Lease::default_lease();
        assert!(lease.is_verb_allowed(Verb::ReadRef));
        assert!(lease.is_verb_allowed(Verb::StageWrite));
        assert!(lease.is_verb_allowed(Verb::ExecuteDryRun));
        assert!(lease.is_verb_allowed(Verb::RunTests));
        assert!(lease.is_verb_allowed(Verb::Commit));
        assert!(lease.is_verb_allowed(Verb::NetLocal));
        assert!(lease.is_verb_allowed(Verb::PushOrigin));
    }

    #[test]
    fn test_default_lease_forbidden_verbs() {
        let lease = Lease::default_lease();
        assert!(lease.is_verb_forbidden(Verb::NetExternal));
        assert!(!lease.is_verb_forbidden(Verb::ReadRef));
    }

    #[test]
    fn test_default_lease_ask_verbs() {
        let lease = Lease::default_lease();
        assert!(lease.is_verb_ask(Verb::PushRemote));
        assert!(lease.is_verb_ask(Verb::NetAllowlisted));
        assert!(lease.is_verb_ask(Verb::RunEphemeral));
    }

    #[test]
    fn test_default_lease_posture_files() {
        let lease = Lease::default_lease();
        assert!(lease
            .posture_files
            .contains(&".claude/hooks/hooks.json".to_string()));
        assert!(lease.posture_files.contains(&"CLAUDE.md".to_string()));
        assert!(lease.posture_files.contains(&".mcp.json".to_string()));
    }

    #[test]
    fn test_default_lease_sensitive_paths() {
        let lease = Lease::default_lease();
        assert!(lease.sensitive_paths.contains(&".env".to_string()));
        assert!(lease.sensitive_paths.contains(&"*.pem".to_string()));
        assert!(lease
            .sensitive_paths
            .contains(&".docker/config.json".to_string()));
        assert!(lease.sensitive_paths.contains(&".kube/config".to_string()));
        assert!(lease
            .sensitive_paths
            .contains(&".git-credentials".to_string()));
        assert!(lease.sensitive_paths.contains(&".pypirc".to_string()));
        assert!(lease
            .sensitive_paths
            .contains(&".terraform/credentials.tfrc.json".to_string()));
        assert!(lease
            .sensitive_paths
            .contains(&".gradle/gradle.properties".to_string()));
        assert!(lease
            .sensitive_paths
            .contains(&".config/gh/hosts.yml".to_string()));
    }

    #[test]
    fn test_default_lease_exclusions() {
        let lease = Lease::default_lease();
        assert!(lease
            .sensitive_path_exclusions
            .contains(&".env.example".to_string()));
        assert!(lease
            .sensitive_path_exclusions
            .contains(&"testdata/**".to_string()));
    }

    #[test]
    fn test_default_lease_approved_hosts() {
        let lease = Lease::default_lease();
        assert!(lease.approved_hosts.contains(&"localhost".to_string()));
        assert!(lease.approved_hosts.contains(&"127.0.0.1".to_string()));
        assert!(lease.approved_hosts.contains(&"::1".to_string()));
        assert!(lease
            .approved_hosts
            .contains(&"host.docker.internal".to_string()));
        assert!(
            !lease.approved_hosts.contains(&"0.0.0.0".to_string()),
            "0.0.0.0 is a bind-all address, not loopback"
        );
    }

    #[test]
    fn test_is_sensitive_path_env() {
        let lease = Lease::default_lease();
        assert!(lease.is_sensitive_path(".env"));
        assert!(lease.is_sensitive_path(".env.local"));
        assert!(lease.is_sensitive_path(".env.production"));
    }

    #[test]
    fn test_is_sensitive_path_new_credentials() {
        let lease = Lease::default_lease();
        assert!(lease.is_sensitive_path(".docker/config.json"));
        assert!(lease.is_sensitive_path(".kube/config"));
        assert!(lease.is_sensitive_path(".git-credentials"));
        assert!(lease.is_sensitive_path(".pypirc"));
        assert!(lease.is_sensitive_path(".terraform/credentials.tfrc.json"));
        assert!(lease.is_sensitive_path(".gradle/gradle.properties"));
        assert!(lease.is_sensitive_path(".config/gh/hosts.yml"));
    }

    #[test]
    fn test_is_sensitive_path_glob() {
        let lease = Lease::default_lease();
        assert!(lease.is_sensitive_path("server.pem"));
        assert!(lease.is_sensitive_path("private.key"));
        assert!(lease.is_sensitive_path(".aws/credentials"));
        assert!(lease.is_sensitive_path(".ssh/id_rsa"));
    }

    #[test]
    fn test_exclusion_before_sensitive_match() {
        let lease = Lease::default_lease();
        // Configured exclusions
        assert!(!lease.is_sensitive_path(".env.example"));
        assert!(!lease.is_sensitive_path(".env.sample"));
        assert!(!lease.is_sensitive_path(".env.template"));
        // testdata/** exclusion
        assert!(!lease.is_sensitive_path("testdata/secret.pem"));
        assert!(!lease.is_sensitive_path("testdata/deep/dir/key.key"));
    }

    #[test]
    fn test_suffix_exclusion_enhanced() {
        let lease = Lease::default_lease();
        // Any path ending in .example, .sample, .template is excluded
        assert!(!lease.is_sensitive_path("config.key.example"));
        assert!(!lease.is_sensitive_path("secrets.pem.sample"));
        assert!(!lease.is_sensitive_path("creds.key.template"));
    }

    #[test]
    fn test_non_sensitive_path() {
        let lease = Lease::default_lease();
        assert!(!lease.is_sensitive_path("src/main.rs"));
        assert!(!lease.is_sensitive_path("README.md"));
        assert!(!lease.is_sensitive_path("package.json"));
    }

    #[test]
    fn test_sink_for_verb() {
        let lease = Lease::default_lease();

        let sink = lease.sink_for_verb(Verb::NetExternal).unwrap();
        assert_eq!(sink.trust, TrustLevel::Untrusted);
        assert_eq!(sink.min_risk, RiskTier::R4);

        let sink = lease.sink_for_verb(Verb::NetLocal).unwrap();
        assert_eq!(sink.trust, TrustLevel::VerifiedInternal);
        assert_eq!(sink.min_risk, RiskTier::R0);

        let sink = lease.sink_for_verb(Verb::Commit).unwrap();
        assert_eq!(sink.trust, TrustLevel::Trusted);
        assert_eq!(sink.min_risk, RiskTier::R0);
    }

    #[test]
    fn test_lease_from_json() {
        let json = r#"{
            "lease_id": "test",
            "mode": "guard",
            "compiler_ceiling": "R3",
            "allowed_verbs": ["read_ref", "stage_write"],
            "forbidden_verbs": ["net_external"],
            "ask_verbs": ["run_ephemeral"],
            "approved_hosts": ["example.com"],
            "approved_remotes": ["origin", "upstream"],
            "allow_delegation": true,
            "observe_only": false
        }"#;

        let lease = Lease::from_json(json).unwrap();
        assert_eq!(lease.lease_id, "test");
        assert!(lease.is_verb_allowed(Verb::ReadRef));
        assert!(lease.is_verb_allowed(Verb::StageWrite));
        assert!(!lease.is_verb_allowed(Verb::NetLocal));
        assert!(lease.is_verb_forbidden(Verb::NetExternal));
        assert!(lease.is_verb_ask(Verb::RunEphemeral));
        assert_eq!(lease.approved_hosts, vec!["example.com"]);
        assert_eq!(lease.approved_remotes, vec!["origin", "upstream"]);
        assert!(lease.allow_delegation);
    }

    #[test]
    fn test_default_lease_allows_delegation_in_clean_sessions() {
        // Default lease allows delegation so Agent tool calls don't prompt in clean sessions.
        // Security gates (secret session, untrusted read) still block/ask in policy.rs.
        let lease = Lease::default_lease();
        assert!(lease.allow_delegation);
        assert!(lease.is_verb_allowed(Verb::Delegate));
    }
}
