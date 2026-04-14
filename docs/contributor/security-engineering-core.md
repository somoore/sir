# Security Engineering Core

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

This is the short version of the engineering guide. Use it when you need the rules quickly and do not want to start from the full architecture reference.

sir is a "sandbox in reverse": `mister-core` (Rust) is a pure, zero-dependency policy oracle that sets the upper bound on what is allowed, and Go collects facts, classifies tool calls, and enforces session-level gates — always stricter than Rust, never looser. Everything below is in service of that split.

> **Note:** sir is experimental. The invariants below are the load-bearing pieces you cannot quietly relax.

When you need broader context, jump to [ARCHITECTURE.md](../../ARCHITECTURE.md) or the package docs for the subsystem you are touching.

## Non-negotiable invariants

1. **Fail closed** on corruption, unreadable state, and bridge errors. Only `os.IsNotExist` may seed fresh defaults.
2. **Resolve path authority** before classification when a path can escape via symlink or traversal.
3. **Go may add restrictions** from session-level facts. It must never override a Rust deny with a looser verdict. Parity is machine-checked.
4. **Posture tamper is session-fatal** — deny-all plus auto-restore from the canonical hook copy.
5. **Raw secrets never go to disk** in telemetry, ledger entries, or investigation evidence. Hash or redact.
6. **New public guarantees need executable tests or contract checks.** Prose alone does not count.

## Where the critical checks live

| Concern | Start here |
| --- | --- |
| Tool → intent classification | [pkg/hooks/toolmap.go](../../pkg/hooks/toolmap.go) |
| Session-fatal preflight checks | [pkg/hooks/evaluate.go](../../pkg/hooks/evaluate.go) |
| Post-tool posture / evidence checks | [pkg/hooks/post_evaluate.go](../../pkg/hooks/post_evaluate.go) |
| Posture hashing and hook restore | [pkg/posture/](../../pkg/posture/) |
| Durable state mutation | [pkg/session/](../../pkg/session/) |
| Policy decision | [mister-core/src/policy.rs](../../mister-core/src/policy.rs) |
| Go/Rust protocol bridge | [pkg/core/](../../pkg/core/) and [mister-shared/src/eval.rs](../../mister-shared/src/eval.rs) |
| Runtime containment | [pkg/runtime/](../../pkg/runtime/) |

## What a safe change looks like

- Keep the trust boundary small.
- Add or update a regression test before changing behavior.
- Update fixture replay or the invariant suite when the user-visible security contract changes.
- Keep docs honest about shipped behavior versus experimental behavior.

## What needs extra scrutiny

- Changes to MSTR/1 framing or request/response fields.
- Anything that widens `approved_hosts`, `approved_remotes`, or MCP trust.
- Anything that changes posture-file handling or deny-all behavior.
- Anything that touches `sir run` containment claims.
- Anything that changes evidence logging or redaction.

## Enforcement Gradient

This is the machine-checked summary of the core enforcement gradient. The matching parity test in `pkg/core/doc_parity_test.go` treats these rows as an executable, contributor-facing contract for the local fallback path.

```text
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
mcp_network_unapproved → ask
mcp_onboarding       → ask
mcp_binary_drift     → ask
mcp_credential_leak  → deny (block)
delete_posture       → ask
stage_write posture  → ask
read_ref sensitive   → ask (marks session secret on approval)
delegate             → deny in secret session, policy otherwise
Everything else      → allow
```

## Scope of MCP gating

`mcp_unapproved` and `mcp_network_unapproved` gate Claude's *arguments* to an MCP server — they do not gate what the MCP server's own process does once invoked. An honest MCP that passes the URL it was given through to the network will be caught when the URL host is not in `approved_hosts`. A malicious MCP that ignores the URL argument and reaches out to its own hard-coded endpoint will not be caught at the verb layer, because sir never sees that call.

Containment for the malicious-MCP case is `sir mcp-proxy` (OS-level sandbox via `sandbox-exec` on macOS, `unshare --net` on Linux), not verb-level gating. The verb-level gate catches Claude being tricked into passing a bad URL to an otherwise trustworthy server; it does not make an approved MCP server safe.

Verdicts for both MCP verbs are always `ask`, never `deny`. The URL classifier is heuristic — field-split, encoded, and server-constructed URLs are intentional blind spots — so a hard-deny would be both noisy and false-confident. Ask lets the user see the decision and opt in.

## MCP trust posture

`sir install` reads `~/.sir/config.json` to determine how discovered MCP servers reach trusted state.

| Posture     | Behavior                                                                                                       |
| ---         | ---                                                                                                            |
| `strict`    | Discovered servers go to `discovered_mcp_servers` and require `sir mcp approve <name>` to enter `approved_mcp_servers`. |
| `standard`  | Discovered servers are auto-added to `approved_mcp_servers` (pre-existing behavior).                           |
| `permissive`| Synonym for `standard`, reserved so a future release can relax defaults further without re-using the name.     |

New installs default to `strict`. Existing installs (detected via the presence of `~/.sir/binary-manifest.json`) default to `standard` to avoid surprising users on upgrade. Approvals made under `strict` are preserved across re-runs of `sir install` — the discovery step only adds *new* servers to `discovered_mcp_servers`, and the existing lease's approvals are carried forward.

`sir mcp approve` records an `MCPApproval` entry carrying `approved_at`, `source_path`, `command`, a sha256 `command_hash` of the resolved binary, and the binary's `command_mod_time`. The hash is empty when the command is launched via `npx`/`uvx` or via `$PATH` with no stable local path — that is honest: we cannot pin what we cannot resolve. Approvals with an empty hash skip the binary-drift gate below; documented behavior.

The binary-drift gate (`mcp_binary_drift`) fires when an approved MCP tool call is dispatched and the command's current hash no longer matches the recorded one. mtime is a fast-path: when the current mtime equals the approval mtime, the gate skips without rehashing. On mismatch, the gate rehashes and decides: matching hash with a different mtime (touch/chmod) → allow; different hash → ask. A missing binary at the recorded path also asks. Verdict is always `ask`. The recovery path is `sir mcp revoke <name> && sir mcp approve <name>` after verifying the change is intended.

`sir mcp revoke <name>` removes the server from `approved_mcp_servers` and deletes the matching `mcp_approvals` record. The server is *not* automatically re-added to `discovered_mcp_servers`; the next `sir install` will surface it again if it is still present in any agent config.

`sir mcp list` prints the current trust state (approved with age, discovered-awaiting-approval with provenance, trusted exempt-from-credential-scan) so the user can see what their project's MCP trust surface looks like without hand-reading the lease JSON.

Important: changing posture from `strict` to `standard`/`permissive` is a trust-loosening change. `sir install` adds the absolute path of `~/.sir/config.json` to the lease's `PostureFiles` list, so agent-initiated `Write`/`Edit` calls against that file hit the existing posture-file ask gate (rule 9 in the non-negotiable invariants). Every write asks regardless of direction — a tightening write is accepted with a single confirm, a loosening write surfaces the change to the user. Manual edits from a terminal outside the agent remain possible; that is consistent with the threat model (direct FS access is outside sir's containment).

## MCP onboarding window

After an MCP server is approved, the onboarding gate (`mcp_onboarding`) bumps subsequent silent-allow calls to `ask` until either the wall-clock window or the per-session call count is exhausted.

Defaults: `mcp_onboarding_window_hours: 24`, `mcp_onboarding_call_count: 20`. Negative values disable the gate; zero and missing both resolve to the default on load (Go JSON cannot distinguish missing from zero).

The gate ends when EITHER threshold is crossed — it is intentionally lenient, because the counter is a friction tool, not a security control. A patient attacker can burn the counter with harmless calls; a 24-hour wait clears the window. The value of the gate is surfacing early activity from a newly-approved server so the user sees what it does, not containing misuse. Containment belongs to `sir mcp-proxy` (OS sandbox).

Session scope: `MCPOnboardingCalls` lives in session state and resets per session. A new agent session re-acquaints the user with the server. Approvals older than the wall-clock window get no onboarding friction regardless of count — by design, long-trusted servers do not re-acquire friction when a new session opens.

Fail-open on config errors: if `~/.sir/config.json` cannot be parsed, the gate skips silently. This is different from the config load in `sir install`, which fails closed. The asymmetry is deliberate: the onboarding gate is UX friction, not a policy boundary, so it should never block a legitimate call due to a user's misconfiguration.

The fallback policy path (`pkg/core/local_fallback_rules.go`) returns Ask for this verb as well, so behavior is consistent whether the Rust oracle or the Go fallback is driving the decision.

## MCP deep verb gating (opt-in, v1 default off)

When `mcp_deep_verb_gating: true` in `~/.sir/config.json`, `mapMCP` inspects approved-MCP tool arguments for conventional field names that reveal shell or filesystem operations, then re-classifies the call through the native verb pipeline:

- Shell-like fields (`command`, `cmd`, `shell`, `script`, `exec`, `run`, `bash`, `sh`, plus common plurals) are passed through `mapShellCommand`. If the resulting verb is in the risky set (`net_external`, `dns_lookup`, `sudo`, `persistence`, `run_ephemeral`, `env_read`, `push_remote`, `push_origin`, `delete_posture`, `net_allowlisted`), the MCP call inherits that verb instead of `execute_dry_run`. Benign shell (e.g., `ls`) stays on the silent-allow path.
- Write-like fields (`path`, `file_path`, `dest`, `destination`, `target`, `output`, `writepath`, plus plurals) are checked against `IsPostureFileResolved` / `IsSensitivePathResolved`. A hit produces a `stage_write` intent with `IsPosture` or `IsSensitive` set, which the Rust policy then gates via `ask`.

Order inside `mapMCP`: server-approval → URL allow-host (`mcp_network_unapproved`) → deep verb gating → fall-through to `execute_dry_run`. Earlier gates take precedence.

Default is `false` in v1 because this gate is heuristic and field-rename evasion is trivial. Before flipping the default in v2, require real telemetry showing (a) low false-positive rate on benign MCP traffic and (b) coverage of the common honest-MCP patterns in the wild.

Honest-MCP framing: this catches servers that wrap shell or filesystem primitives under conventional field names (e.g., `postgres.exec_shell`, `filesystem.write_file`). It does not catch servers that obfuscate by design — renamed keys, base64-encoded payloads, and server-constructed commands all evade it. A malicious MCP is still the domain of `sir mcp-proxy` and OS sandboxing, not verb-level gating.

Config fail-open: same pattern as the onboarding gate — config parse errors skip the gate rather than blocking the call.

## Required verification for security-sensitive changes

```bash
go test ./...
cargo test --locked
make replay
make bench-check
go test ./cmd/sir -run TestSecurityInvariantSuiteV1
```

If the change affects docs, versions, or contributor promises:

```bash
make public-contract
```
