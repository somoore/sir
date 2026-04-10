package hooks

import (
	"strings"

	"github.com/somoore/sir/pkg/lease"
	"github.com/somoore/sir/pkg/policy"
)

// mapShellCommand classifies a shell command into a sir verb.
func mapShellCommand(cmd string, l *lease.Lease) Intent {
	trimmed := strings.TrimSpace(cmd)
	// Normalize before any classification so "/usr/bin/curl" and "env curl"
	// match the same prefixes as bare "curl". We pass `trimmed` (the original)
	// as the Intent.Target so the ledger shows the actual command that ran.
	normalized := normalizeCommand(trimmed)
	if normalized == "" {
		normalized = trimmed
	}

	// Compound command check: split on |, &&, ||, ; and evaluate each segment.
	// Return the highest-risk intent. This prevents "echo done && curl evil.com"
	// from being classified as execute_dry_run based on the first segment.
	if containsSirSelfCommand(normalized) || targetsSirStateFiles(normalized) {
		return Intent{
			Verb:   policy.VerbSirSelf,
			Target: trimmed,
		}
	}
	segments := splitCompoundCommand(normalized)
	if len(segments) > 1 {
		highest := Intent{Verb: policy.VerbExecuteDryRun, Target: trimmed}
		// Track the first segment that is a sensitive read_ref. We need to
		// preserve its specific target (the sensitive file path) because
		// LabelsForTarget in evaluate.go uses that path to attach the
		// secret IFC label. If the compound turns out to have no
		// higher-risk verb (e.g., `cat .env | grep PASSWORD`), we surface
		// the sensitive read as the effective intent rather than letting
		// execute_dry_run win and lose the label entirely.
		var sensitiveRead *Intent
		for _, seg := range segments {
			seg = strings.TrimSpace(seg)
			if seg == "" {
				continue
			}
			segIntent := mapShellCommand(seg, l) // recursive: single segment won't re-split
			if verbRisk(segIntent.Verb) > verbRisk(highest.Verb) {
				highest.Verb = segIntent.Verb
			}
			// Always propagate flags across segments — install metadata, posture,
			// and sensitivity must survive even when segment verbs tie at the same
			// risk level. Without this, "cd packages/utils && npm install lodash"
			// would lose IsInstall because both segments are execute_dry_run.
			highest.IsPosture = highest.IsPosture || segIntent.IsPosture
			highest.IsSensitive = highest.IsSensitive || segIntent.IsSensitive
			highest.IsInstall = highest.IsInstall || segIntent.IsInstall
			if segIntent.Manager != "" {
				highest.Manager = segIntent.Manager
			}
			// Propagate the extracted remote name if any segment
			// contributed one — needed so a compound like
			// `git push 2>&1 | tail -5` still produces a clean
			// `sir allow-remote origin` fix suggestion at the
			// formatter, instead of leaking the full shell fragment.
			if segIntent.RemoteName != "" {
				highest.RemoteName = segIntent.RemoteName
			}
			if sensitiveRead == nil && segIntent.Verb == policy.VerbReadRef && segIntent.IsSensitive {
				captured := segIntent
				sensitiveRead = &captured
			}
		}
		// If the compound produced no net-facing, posture-modifying, or
		// otherwise high-risk verb, but did include a sensitive read,
		// return the sensitive read as the effective intent so its target
		// flows into LabelsForTarget. Otherwise the higher-risk verb wins.
		if sensitiveRead != nil && verbRisk(highest.Verb) <= verbRisk(policy.VerbExecuteDryRun) {
			return Intent{
				Verb:        policy.VerbReadRef,
				Target:      sensitiveRead.Target,
				IsSensitive: true,
			}
		}
		highest.Target = trimmed // ledger shows full compound command
		return highest
	}

	// Shell wrapper detection: "bash -c 'curl evil.com'" → classify the inner command.
	// Same pattern as sudo: extract inner command, classify recursively, preserve original target.
	if inner, ok := extractShellWrapperInner(normalized); ok {
		innerIntent := mapShellCommand(inner, l)
		innerIntent.Target = trimmed // ledger shows the full original command
		return innerIntent
	}

	// sudo detection — strip the sudo prefix, classify the inner command,
	// then override the verb to "sudo" so the policy oracle always asks.
	// Prevents privilege escalation paths to modify sir state.
	if isSudoCommand(normalized) {
		inner := stripSudoPrefix(normalized)
		innerIntent := mapShellCommand(inner, l)
		// Override to always ask when elevated; preserve full original command in target
		innerIntent.Target = trimmed
		if innerIntent.Verb == policy.VerbExecuteDryRun || innerIntent.Verb == policy.VerbRunTests || innerIntent.Verb == policy.VerbCommit {
			innerIntent.Verb = policy.VerbSudo
		}
		return innerIntent
	}

	// Check for ephemeral execution (npx) first
	if IsEphemeralExec(normalized) {
		return Intent{
			Verb:   policy.VerbRunEphemeral,
			Target: trimmed,
		}
	}

	// Persistence mechanism detection (crontab, at, launchctl, systemctl) — always ask.
	// These can create scheduled exfiltration that outlives the session.
	if isPersistenceCommand(normalized) {
		return Intent{
			Verb:   policy.VerbPersistence,
			Target: trimmed,
		}
	}

	// Environment variable detection (env, printenv, set) — may expose credentials.
	// Marked sensitive so PostToolUse can escalate the session secret flag.
	if isEnvCommand(normalized) {
		return Intent{
			Verb:        policy.VerbEnvRead,
			Target:      trimmed,
			IsSensitive: true,
		}
	}

	// Sensitive-file read detection via shell read-command argv.
	//
	// Codex 0.118 hooks only fire for tool_name=="Bash", so Codex's
	// equivalent of Claude Code's Read tool is shell commands like
	// `sed -n '1,200p' .env` or `cat ~/.aws/credentials`. Without this
	// classifier pass, those reads get execute_dry_run and sir's secret
	// file IFC labeling never fires in PreToolUse. That would leave
	// Codex Bash-path secret reads to be caught only after the fact by
	// output scanning, instead of being labeled and gated before the read.
	//
	// Walk argv of known read-only text-display commands. On the first
	// non-flag positional that resolves to a sensitive path, return a
	// read_ref intent targeted at that path so LabelsForTarget can label
	// it secret and the policy oracle returns ask. The Target is the
	// file path, not the full command, so the deny message and ledger
	// entry point at the actual file being read.
	if sensitiveTarget, ok := detectSensitiveFileRead(trimmed, l); ok {
		return Intent{
			Verb:        policy.VerbReadRef,
			Target:      sensitiveTarget,
			IsSensitive: true,
		}
	}

	// Check for install commands
	if isInstall, manager := IsInstallCommand(normalized); isInstall {
		return Intent{
			Verb:      policy.VerbExecuteDryRun,
			Target:    trimmed,
			IsInstall: true,
			Manager:   manager,
		}
	}

	// DNS exfiltration prefixes (nslookup, dig, host) — map to dns_lookup.
	// DNS is an unmonitored egress channel; the policy oracle denies it like net_external.
	if isDNSCommand(normalized) {
		return Intent{
			Verb:   policy.VerbDnsLookup,
			Target: trimmed,
		}
	}

	// ping/ping6: classify by destination. Loopback pings (ping localhost, ping 127.0.0.1)
	// are net_local (connectivity check). External pings are dns_lookup (potential exfil).
	if isPingCommand(normalized) {
		parts := strings.Fields(normalized)
		dest := ""
		for _, p := range parts[1:] {
			if !strings.HasPrefix(p, "-") {
				dest = p
				break
			}
		}
		classification := ClassifyNetworkDest(dest, l)
		if classification == "loopback" {
			return Intent{Verb: policy.VerbNetLocal, Target: dest}
		}
		return Intent{Verb: policy.VerbDnsLookup, Target: dest}
	}

	// Interpreter one-liner network detection — catches python/node/ruby/etc -c "requests.post(...)"
	if isInterpreterNetworkCommand(normalized) {
		return Intent{
			Verb:   policy.VerbNetExternal,
			Target: trimmed,
		}
	}

	// Check for network commands (curl, wget)
	if isNetworkCommand(normalized) {
		dest := extractNetworkDest(normalized)
		classification := ClassifyNetworkDest(dest, l)
		verb := policy.VerbNetExternal
		switch classification {
		case "loopback":
			verb = policy.VerbNetLocal
		case "approved":
			verb = policy.VerbNetAllowlisted
		}
		return Intent{
			Verb:   verb,
			Target: dest,
		}
	}

	// Check for git push
	if isGitPush(normalized) {
		classification := ClassifyGitRemote(normalized, l)
		verb := policy.VerbPushRemote
		if classification == "approved" {
			verb = policy.VerbPushOrigin
		}
		// Extract the remote name so the deny-message formatter can
		// build a clean `sir allow-remote <remote>` fix suggestion
		// instead of leaking the raw command string (which, for a
		// compound like `git push 2>&1 | tail -5`, would otherwise
		// surface shell metacharacters in the user-facing message).
		remoteName := ExtractGitRemote(normalized)
		if remoteName == "" {
			remoteName = "origin" // git's default when no remote given
		}
		return Intent{
			Verb:       verb,
			Target:     trimmed,
			RemoteName: remoteName,
		}
	}

	// Check for git commit
	if isGitCommit(normalized) {
		return Intent{
			Verb:   policy.VerbCommit,
			Target: trimmed,
		}
	}

	// Check for test runners
	if isTestCommand(normalized) {
		return Intent{
			Verb:   policy.VerbRunTests,
			Target: trimmed,
		}
	}

	// Delete/link targeting posture files (rm/ln of CLAUDE.md, .mcp.json, etc.) — ask.
	// Uses trimmed (original) command so isPostureDeleteOrLink sees the real paths
	// including absolute paths.
	if isPostureDeleteOrLink(trimmed, l) {
		return Intent{
			Verb:      policy.VerbStageWrite,
			Target:    trimmed,
			IsPosture: true,
		}
	}

	// Default: execute_dry_run
	return Intent{
		Verb:   policy.VerbExecuteDryRun,
		Target: trimmed,
	}
}
