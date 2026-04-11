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
mcp_credential_leak  → deny (block)
delete_posture       → ask
stage_write posture  → ask
read_ref sensitive   → ask (marks session secret on approval)
delegate             → deny in secret session, policy otherwise
Everything else      → allow
```

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
