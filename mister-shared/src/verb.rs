// ---------------------------------------------------------------------------
// Verb (Intent classification)
// ---------------------------------------------------------------------------

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Verb {
    NetLocal,             // curl/wget to loopback
    NetAllowlisted,       // curl/wget to approved_hosts
    NetExternal,          // curl/wget to all other hosts
    PushOrigin,           // git push to approved_remotes
    PushRemote,           // git push to unapproved remotes
    RunEphemeral,         // npx (ephemeral remote code execution)
    ReadRef,              // File read
    StageWrite,           // File write
    ExecuteDryRun,        // Shell command
    RunTests,             // Test runner
    Commit,               // git commit
    ListFiles,            // File listing
    SearchCode,           // Code search
    EnvRead,              // env/printenv/set commands that reveal environment variables
    DnsLookup,            // nslookup/dig/host (network egress via DNS)
    Persistence,          // crontab/at/launchctl/systemctl
    Sudo,                 // elevated commands
    DeletePosture,        // rm/ln targeting posture files
    Delegate,             // Agent tool delegation
    McpUnapproved,        // MCP server not in approved list
    McpCredentialLeak,    // credential-looking MCP arguments to untrusted server
    McpInjectionDetected, // hostile MCP output detected post-call
    CredentialDetected,   // structured credential detected in tool output
    ElicitationHarvest,   // suspicious harvesting phrasing in agent prompt
    SirSelf,              // sir CLI self-modification (install/uninstall/clear)
}

impl Verb {
    pub const ALL: [Verb; 25] = [
        Verb::NetLocal,
        Verb::NetAllowlisted,
        Verb::NetExternal,
        Verb::PushOrigin,
        Verb::PushRemote,
        Verb::RunEphemeral,
        Verb::ReadRef,
        Verb::StageWrite,
        Verb::ExecuteDryRun,
        Verb::RunTests,
        Verb::Commit,
        Verb::ListFiles,
        Verb::SearchCode,
        Verb::EnvRead,
        Verb::DnsLookup,
        Verb::Persistence,
        Verb::Sudo,
        Verb::DeletePosture,
        Verb::Delegate,
        Verb::McpUnapproved,
        Verb::McpCredentialLeak,
        Verb::McpInjectionDetected,
        Verb::CredentialDetected,
        Verb::ElicitationHarvest,
        Verb::SirSelf,
    ];

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Verb> {
        match s {
            "net_local" => Some(Verb::NetLocal),
            "net_allowlisted" => Some(Verb::NetAllowlisted),
            "net_external" => Some(Verb::NetExternal),
            "push_origin" => Some(Verb::PushOrigin),
            "push_remote" => Some(Verb::PushRemote),
            "run_ephemeral" => Some(Verb::RunEphemeral),
            "read_ref" => Some(Verb::ReadRef),
            "stage_write" => Some(Verb::StageWrite),
            "execute_dry_run" => Some(Verb::ExecuteDryRun),
            "run_tests" => Some(Verb::RunTests),
            "commit" => Some(Verb::Commit),
            "list_files" => Some(Verb::ListFiles),
            "search_code" => Some(Verb::SearchCode),
            "env_read" => Some(Verb::EnvRead),
            "dns_lookup" => Some(Verb::DnsLookup),
            "persistence" => Some(Verb::Persistence),
            "sudo" => Some(Verb::Sudo),
            "delete_posture" => Some(Verb::DeletePosture),
            "delegate" => Some(Verb::Delegate),
            "mcp_unapproved" => Some(Verb::McpUnapproved),
            "mcp_credential_leak" => Some(Verb::McpCredentialLeak),
            "mcp_injection_detected" => Some(Verb::McpInjectionDetected),
            "credential_detected" => Some(Verb::CredentialDetected),
            "elicitation_harvest" => Some(Verb::ElicitationHarvest),
            "sir_self" => Some(Verb::SirSelf),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Verb::NetLocal => "net_local",
            Verb::NetAllowlisted => "net_allowlisted",
            Verb::NetExternal => "net_external",
            Verb::PushOrigin => "push_origin",
            Verb::PushRemote => "push_remote",
            Verb::RunEphemeral => "run_ephemeral",
            Verb::ReadRef => "read_ref",
            Verb::StageWrite => "stage_write",
            Verb::ExecuteDryRun => "execute_dry_run",
            Verb::RunTests => "run_tests",
            Verb::Commit => "commit",
            Verb::ListFiles => "list_files",
            Verb::SearchCode => "search_code",
            Verb::EnvRead => "env_read",
            Verb::DnsLookup => "dns_lookup",
            Verb::Persistence => "persistence",
            Verb::Sudo => "sudo",
            Verb::DeletePosture => "delete_posture",
            Verb::Delegate => "delegate",
            Verb::McpUnapproved => "mcp_unapproved",
            Verb::McpCredentialLeak => "mcp_credential_leak",
            Verb::McpInjectionDetected => "mcp_injection_detected",
            Verb::CredentialDetected => "credential_detected",
            Verb::ElicitationHarvest => "elicitation_harvest",
            Verb::SirSelf => "sir_self",
        }
    }
}

impl fmt::Display for Verb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verb_roundtrip() {
        for v in &Verb::ALL {
            assert_eq!(Verb::from_str(v.as_str()), Some(*v));
        }
    }
}
