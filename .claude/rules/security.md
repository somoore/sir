# Security Rules

## Five Detections

1. **Secret Access & Egress Control:** Sensitive files labeled at read time. Secret reads → ask. Secret session + external egress → deny. Secret session + approved host/push → ask. Turn-scoped by default (clears on next UserPromptSubmit).

2. **Post-Install Posture Tampering:** Sentinel files hashed before/after package installs. Mutation detected in PostToolUse → alert + posture hash update.

3. **Unauthorized Posture Changes:** Writes to posture files always ask. Hook config tampering → session-fatal deny-all + auto-restore from canonical copy.

4. **MCP Defense:** Response injection scanning (PostToolUse, first+last 100KB). Argument credential scanning (PreToolUse, **all untrusted MCP args regardless of session state**, skip TrustedMCPServers). Posture elevation on detection.

5. **Elicitation & Delegation Gating:** Elicitation prompts scanned for credential harvesting (warn only). SubagentStart checks lease delegation permission, secret session (deny), and posture state.

## Enforcement Gradient

```
net_external         → deny (always, regardless of session state)
dns_lookup           → deny (same as net_external)
push_remote          → ask (deny if secret session)
push_origin          → ask if secret session, allow otherwise
net_allowlisted      → ask
run_ephemeral        → ask (always)
env_read             → ask (marks session secret on approval)
persistence          → ask
sudo                 → ask
sir_self             → ask (self-protection)
mcp_unapproved       → ask
mcp_credential_leak  → deny (block, TrustedMCPServers exempt)
delete_posture       → ask
stage_write posture  → ask
read_ref sensitive   → ask (marks session secret on approval)
delegate             → deny in secret session, policy otherwise
Everything else      → allow
```

## Fail-Closed Rules

- `loadLease`: default only on `os.IsNotExist`. Corruption → error → guardDeny.
- `loadOrCreateSession`: new session only on `os.IsNotExist`. Corruption → error → guardDeny.
- `EvaluateSubagentStart`: allow only on `os.IsNotExist` (no session yet). Corruption → error → guardDeny.
- Empty `SessionHash` → fail (not pass). Attacker cannot bypass integrity by clearing the hash.
- Missing mister-core binary → loud stderr warning + defensive Go fallback (`pkg/core/core.go::localEvaluate`). The fallback is a deliberately restrictive subset of the Rust policy; `TestLocalEvaluate_VerbParity` and `TestEnforcementGradientDocParity` enforce that it is never more permissive than Rust. If mister-core crashes or returns non-zero, that IS a hard deny (`pkg/core/core.go:82-89`).
- Internal hook errors → `guardDeny()` emitting well-formed deny JSON and `os.Exit(0)`.

## Shell Classification

`normalizeCommand` runs before all classifiers:
- Strips absolute paths (`/usr/bin/curl` → `curl`)
- Strips `env` prefix and flags (`env -i FOO=bar curl` → `curl`)
- Strips inline variable assignments (`DUMMY=1 curl` → `curl`) — also without `env` prefix

`splitCompoundCommand` splits on `|`, `&&`, `||`, `;` (quote-aware). Each segment classified independently. `verbRisk` picks highest-risk segment. Install metadata (`IsInstall`, `Manager`) OR-merges across segments regardless of risk level.

`gitSubcommandIs` scans past global flags (`-c`, `--git-dir`, `--work-tree`, `--namespace`, `--config-env`, `--exec-path`, `--html-path`) to find the subcommand. Handles `--flag=value` and valued flags.

`isInterpreterNetworkCommand` catches combined flags (`-uc`, `-pe`) by checking if a short flag ends with `c`, `e`, or `r`.

`extractShellWrapperInner` handles `bash/sh/zsh/dash/ksh -c "..."` (including combined flags like `-xc`, flags before `-c` like `-e -c`, and both single/double quoting) by extracting the inner command and recursively classifying via `mapShellCommand`.

`containsSirSelfCommand` splits on compound operators and checks each segment for sir self-modification commands. `targetsSirStateFiles` detects `sed`/`python`/`chmod`/`mv`/`cp`/`tee` targeting `~/.sir/` paths and `~/.claude/settings.json`.

## Path Canonicalization

- `matchPathTail(path, pattern)` matches the last N path segments (where N = segments in pattern). Absolute paths, traversal paths, and symlinks all fall through to tail-based matching.
- `ResolveTarget(projectRoot, target)` normalizes projectRoot-relative paths.
- `IsSensitivePathResolvedIn(projectRoot, target, lease)` is the canonical check for PreToolUse + PostToolUse sensitive file detection.
- Exclusions (`.env.example`, `.env.sample`, `.env.template`, `testdata/**`, `fixtures/**`) checked BEFORE sensitive path matches.

## MCP Defense Details

- Response scanning: first 100KB + last 100KB for payloads >200KB. Prevents OOM.
- Four pattern categories: authority framing, exfil instruction, credential harvest, hidden markers (zero-width chars, CSS hiding).
- Injection detection raises session posture. PendingInjectionAlert overlays on the mister-core verdict WITHOUT early return: deny stays deny, allow upgrades to ask, ask gets warning prepended. Never downgrades a deny.
- Credential argument scanning runs on **all untrusted MCP args regardless of session state**, gated only on `!lease.IsTrustedMCPServer(server)`. Rationale: a developer pasting `sk_live_...` into an MCP prompt must be caught even in a non-secret session, because the paste itself is the credential disclosure.
- Elicitation scanning: warn via stderr, log to ledger. Never block (breaks legitimate MCP servers).

## Credential Output Scanning

- 18 regex patterns + Luhn (credit cards) + SSA area validation (SSN, rejects 000/666/9xx) + Shannon entropy (>4.5 bits/char, >32 chars).
- High confidence: AWS access key, 6 GitHub PAT variants, Slack tokens, Stripe live keys, Google API key, OpenAI, PEM private key headers.
- Medium confidence with validators: JWT, SSN, credit card (Luhn), high-entropy tokens.
- Scans Read/Edit/Bash tool output in PostToolUse. NOT MCP output (already covered by injection scanning).
- Consequence: IFC label escalation (session marked secret), not block.
- First 100KB + last 100KB for large outputs (>200KB).
- Pattern names only logged — never actual credential values.

## Ledger Integrity

- Hash chain uses **length-prefixed** encoding: `uint64(len) || bytes` per field. Never delimiter-joined. Delimiter injection collisions are a security bug.
- Append-only. `sir log verify` walks the chain and reports the first corruption.
- v2.1 format is incompatible with v2.0 pipe-joined ledgers. Old ledgers must be archived and a fresh chain started.
