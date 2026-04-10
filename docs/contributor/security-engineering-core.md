# Security Engineering Core

This is the short version of the engineering guide. Use it when you need the
rules quickly and do not want to start from the full architecture reference.

When you need broader context, jump to [ARCHITECTURE.md](../../ARCHITECTURE.md)
or the package docs for the subsystem you are touching.

## Non-negotiable invariants

1. Fail closed on corruption, unreadable state, and bridge errors.
2. Resolve path authority before classification when a path can escape via
   symlink or traversal.
3. Go may add restrictions from session-level facts. It must never override a
   Rust deny with a looser verdict.
4. Posture tamper is a session-fatal event.
5. Raw secrets never go to disk in telemetry or investigation evidence.
6. New public guarantees need executable tests or contract checks.

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

- keep the trust boundary small
- add or update a regression test before changing behavior
- update fixture replay or the invariant suite when the user-visible security
  contract changes
- keep docs honest about shipped behavior versus experimental behavior

## What needs extra scrutiny

- changes to MSTR/1 framing or request/response fields
- anything that widens `approved_hosts`, `approved_remotes`, or MCP trust
- anything that changes posture-file handling or deny-all behavior
- anything that touches `sir run` containment claims
- anything that changes evidence logging or redaction

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
