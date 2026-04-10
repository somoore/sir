# Architecture Rules

## File Ownership

| Agent/Scope | Files |
|------------|-------|
| Rust policy | `mister-core/src/*.rs`, `mister-shared/src/lib.rs` |
| Go hooks | `pkg/hooks/*.go`, `pkg/core/core.go` |
| Go CLI | `cmd/sir/main.go`, `cmd/sir/version.go` |
| Go state | `pkg/session/session.go`, `pkg/lease/lease.go`, `pkg/ledger/ledger.go` |
| Telemetry | `pkg/telemetry/otlp.go` |
| Tests | `*_test.go`, `tests/`, `testdata/` |

## Verb Model

Go verb strings and Rust `Verb::from_str` must match exactly:

```
net_local, net_allowlisted, net_external, push_origin, push_remote,
run_ephemeral, read_ref, stage_write, execute_dry_run, run_tests,
commit, list_files, search_code, env_read, dns_lookup, persistence,
sudo, delete_posture, delegate, mcp_unapproved, mcp_credential_leak,
mcp_injection_detected, credential_detected, elicitation_harvest,
sir_self
```

Adding a verb requires matching entries in `mister-shared/src/lib.rs`, `mister-core/src/policy.rs`, and a row in `pkg/core/core_test.go::TestLocalEvaluate_VerbParity`.

## State Locations

All sir state at `~/.sir/projects/<sha256-of-project-root>/`:
- `ledger.jsonl` — append-only hash-chained decision log (v2.1 length-prefixed hash format)
- `lease.json` — active lease (sensitive_paths, approved_hosts, approved_remotes, posture_files, TrustedMCPServers)
- `session.json` — session state (secret flag, posture, MCP taint, injection alerts, session hash, instruction hashes)
- `hooks-canonical.json` — machine-wide backup at `~/.sir/hooks-canonical.json`

Global hooks in `~/.claude/settings.json`. No repo-local `.claude/.sir/` directory.

## Go-Rust Policy Boundary

- Go enforces session-level invariants (deny-all, posture checks, injection alerts, credential scanning, delegation in secret session).
- Rust enforces lease-level policy (verb allowed/forbidden/ask, IFC check_flow, sink trust).
- **Go NEVER overrides a Rust deny.** Go MAY upgrade a Rust allow to ask (posture elevation, injection alert).
- Enforced by `parity_test.go` + `TestLocalEvaluate_VerbParity`. When adding a new verb, add a row to the parity table.

## Hook JSON Schema

Claude Code requires ALL hook events to use:
```json
"EventName": [{ "hooks": [{ "type": "command", "command": "...", "timeout": N }] }]
```
Tool events add `"matcher": ".*"`. Non-tool events omit matcher. The flat format `[{ "type": "command", "command": "..." }]` is SILENTLY REJECTED by Claude Code.

`generateHooksConfig()` uses `[]interface{}` with `map[string]interface{}` elements. A type mismatch with the merge loop silently produces nil hooks arrays — see historic bug resolution for the pattern.

## OTLP Telemetry

- Activated by `SIR_OTLP_ENDPOINT` env var. No-op when unset (zero goroutines, zero allocations).
- OTLP/HTTP JSON to `/v1/logs`. 200ms timeout. Fire-and-forget goroutine. 500ms shutdown bound.
- Emits `sir.*` prefixed attributes. Secret-labeled targets SHA-256 hashed. Network targets reduced to hostname only via `RedactTarget`. Reason field redacted to verb + verdict.
- `sir.ledger.index` and `sir.ledger.hash` enable SIEM-to-local forensic cross-reference via `sir explain --index N`.

## Update Model

- No self-updater, no background checker, no `sir update` subcommand.
- `sir version --check` queries GitHub Releases API (stdlib HTTP, 5s timeout), prints status, exits 0 on errors.
- `install.sh` is idempotent and the ONLY update path. It preserves `~/.sir/` state.
- `install.sh` downgrade guard: reads target version from `cmd/sir/version.go::Version`, compares to running `sir version` via `sort -V`, aborts on older-over-newer unless `SIR_ALLOW_DOWNGRADE=1`.
