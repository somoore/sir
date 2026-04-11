# sir — Sandbox in Reverse

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

Security runtime for AI coding agents. Go CLI, Rust policy oracle, quiet on normal coding, loud on dangerous transitions.

## Core model

- `sir` collects facts, manages state, writes the ledger, and talks to host-agent hooks.
- `mister-core` decides allow / deny / ask from normalized inputs.
- Go may add restrictions from facts Rust cannot see. Go must never widen a Rust deny.

## Layout

```text
cmd/sir/        CLI entrypoints
pkg/agent/      Claude / Gemini / Codex adapters
pkg/hooks/      hook handlers, shell mapping, labels, MCP scans
pkg/session/    durable posture and secret-session state
pkg/ledger/     append-only decision history
pkg/runtime/    optional below-hook containment
pkg/mcp/        MCP inventory and rewrite
pkg/core/       MSTR/1 bridge to mister-core
mister-core/    Rust policy oracle
mister-shared/  Rust shared protocol and types
testdata/       fixtures and invariant inputs
tests/          higher-level integration coverage
```

## Non-negotiables

1. Go stays standard-library only unless there is a reviewed exception.
2. `mister-core` and `mister-shared` stay zero-dependency and zero-unsafe.
3. Corrupted state fails closed. Only `os.IsNotExist` can seed fresh defaults.
4. Go verb strings must stay aligned with Rust verb parsing.
5. Session mutation must stay lock-safe and atomic on disk.
6. Path-sensitive checks must resolve symlinks before classification.
7. The ledger and telemetry never store raw secrets.
8. Hook handlers return well-formed deny JSON on internal errors.
9. Posture-file writes always ask.
10. Public guarantees need tests or contract checks.

## Working docs

- [ARCHITECTURE.md](ARCHITECTURE.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md)
- [docs/contributor/security-engineering-core.md](docs/contributor/security-engineering-core.md)
- [docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md)
- [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md)
