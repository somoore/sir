# Validation Summary

This is the short production-facing summary of the evidence behind sir's current claims. The detailed exploratory writeups and historical findings packs were intentionally removed from the active repo surface to keep the release docs tight; they remain recoverable in git history when needed.

## What we claim today

- sir provides the strongest **hook-mediated** runtime security we know of for AI coding agents.
- Claude Code is the reference-support target.
- Gemini CLI is near-parity on tool-path coverage, with fewer lifecycle hooks.
- Codex support is real but limited by the current upstream Bash-only hook surface.
- `sir run <agent>` is a **measured preview** below-hook containment path on macOS and Linux, not yet a cross-platform transparent egress firewall.

## Evidence that supports those claims

### Real-session validation

- 65 real Claude Code sessions across confounding-free, adversarial, and smoke packs
- 0 normal operations interrupted
- 0 boundary violations observed in those packs

### Automated verification

- Large Go unit/integration test suite covering hooks, ledger integrity, install/status flows, parity, MCP scanning, managed mode, and observability
- Versioned end-to-end security invariant fixtures covering secret-read egress denial, MCP credential leak denial, hook tamper restore, managed-mode refusal, and lineage-carrying push gating
- Rust unit tests for the policy oracle and shared protocol surface
- Replay harness for normalized hook payload fixtures via `make replay`
- Benchmark budget enforcement for the hook path, ledger path, session mutation, runtime containment bookkeeping, MCP inventory parsing, and `sir explain`
- Durable runtime receipts in `sir status` / `sir doctor` that record the last contained launch mode, allowlist size, and blocked/allowed egress counts
- Public-contract test that keeps the shipped docs and toolchain promises aligned with the codebase

### Supply-chain and release verification

- Reproducible build checks in CI
- Signed release artifacts and SBOM generation
- Zero external Rust crate dependencies in `mister-core` and `mister-shared`

## How to re-run the important checks

- Fast local confidence: `go test ./... && cargo test --locked`
- Replay normalized fixtures: `make replay`
- Enforce perf budgets: `make bench-check`
- Verify contributor-facing contract: `make public-contract`
- Follow the release/operator runbook: [Security Verification Guide](security-verification-guide.md)

## What is no longer in the active docs set

These artifact types were removed from the production repo surface on purpose:

- launch copy
- GTM notes
- internal phase trackers
- one-off smoke-test narrative writeups
- exploratory gap-closure narratives that duplicate shipped code/tests

If you need them for audit or historical analysis, use `git log --follow` on the removed file paths or inspect the tagged release history.
