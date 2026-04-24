# Validation Summary

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

This is the short production-facing summary of the evidence behind sir's current claims. sir is an experimental security runtime for AI coding agents: it intercepts tool calls at the hook layer, routes them through a Rust policy oracle, and tracks information flow across a session so that a secret read in turn N can gate an egress attempt in turn N+1.

This page is the evidence view behind those claims. The detailed exploratory writeups and historical findings packs were intentionally removed from the active repo surface to keep the release docs tight; they remain recoverable in git history when needed.

## What we claim today

We try to be narrow and honest about what v1 actually does, rather than claim protection sir cannot deliver:

- sir provides **hook-mediated** runtime policy for AI coding agents — it mediates *intents* crossing the tool boundary, not syscalls. If the agent bypasses the hook layer, sir cannot see it.
- Claude Code is the reference-support target because it has the richest hook surface.
- Gemini CLI is near-parity on tool-path coverage, with fewer lifecycle hooks.
- Codex support is real but limited by missing lifecycle hooks and upstream hook delivery gaps.
- `sir run <agent>` is a **measured preview** below-hook containment path on macOS and Linux, not yet a cross-platform transparent egress firewall.
- MCP injection detection is heuristic (~50 regex patterns). The fail-closed backstop is downstream IFC, not the literal scanner.
- The default lease is permissive to reduce developer friction. Hardened deployments should use managed mode.

What we do **not** claim: model-internal taint tracking, protection from novel shell wrappers below the classifier, or complete host containment on every platform. Those are v2+ work.

## Evidence that supports those claims

### Real-session validation

- 65 real Claude Code sessions across confounding-free, adversarial, and smoke packs.
- 0 normal operations interrupted.
- 0 boundary violations observed in those packs.

### Automated verification

- Large Go unit and integration test suite covering hooks, ledger integrity, install/status flows, parity, MCP scanning, managed mode, and observability.
- Versioned end-to-end security invariant fixtures covering secret-read egress denial, MCP credential leak denial, hook tamper restore, managed-mode refusal, and lineage-carrying push gating.
- Rust unit tests for the policy oracle and shared protocol surface.
- Replay harness for normalized hook payload fixtures via `make replay`.
- Benchmark budget enforcement for the hook path, ledger path, session mutation, runtime containment bookkeeping, MCP inventory parsing, and `sir explain`.
- Durable runtime receipts in `sir status` and `sir doctor` that record the last contained launch mode, allowlist size, and blocked/allowed egress counts.
- Public-contract test that keeps the shipped docs and toolchain promises aligned with the codebase.

### Supply-chain and release verification

- Reproducible build checks in CI.
- Signed release artifacts and SBOM generation.
- Zero external Rust crate dependencies in `mister-core` and `mister-shared`.

## How to re-run the important checks

Every check here exercises the real evaluation path. There are no mock evaluators, and the same hook handlers that run under Claude Code run under the test harness.

- **Fast local confidence:** `go test ./... && cargo test --locked`
- **Replay normalized fixtures:** `make replay`
- **Enforce perf budgets:** `make bench-check`
- **Verify contributor-facing contract:** `make public-contract`
- **Follow the release/operator runbook:** [Security Verification Guide](security-verification-guide.md)
- **Understand the in-scope boundary before evaluating:** [sir Threat Model](sir-threat-model.md)

> **Note:** If any of these produce a verdict that contradicts a documented guarantee, treat it as a finding and open an issue — or a private advisory for in-scope security boundaries.

## What is no longer in the active docs set

These artifact types were removed from the production repo surface on purpose:

- Launch copy.
- GTM notes.
- Internal phase trackers.
- One-off smoke-test narrative writeups.
- Exploratory gap-closure narratives that duplicate shipped code and tests.

If you need them for audit or historical analysis, use `git log --follow` on the removed file paths or inspect the tagged release history.
