# Contributing to sir

sir is an experimental security runtime for AI coding agents. It is a "sandbox in reverse": instead of wrapping an agent process from below with syscalls or filesystem jails, sir constrains the agent from above by intercepting tool calls at the host's hook layer, normalizing them into verbs, and deciding allow / ask / deny through a pure Rust policy oracle. Information flow control propagates taint across operations, so a secret read contaminates any downstream write, commit, or push.

> **Note:** If that framing is new, read [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md) before this file. The single invariant that shapes every contribution: `mister-core` (Rust) is the upper bound on what sir will allow, and the Go layer may only be stricter, never looser.

sir is a security tool and is still experimental. Keep changes small, explicit, and test-backed. When in doubt, fail closed.

## Setup

Prerequisites:

- **Rust** (1.94.0+): [rustup.rs](https://rustup.rs/)
- **Go** (1.22+): [go.dev/dl](https://go.dev/dl/)
- `make` is optional but convenient.

Build and install locally:

```bash
make build
make install
```

## Start clean

```bash
git fetch origin
git switch -c my-change origin/main
make contributor-check
```

If `make contributor-check` fails, fix the branch or worktree first.

Start with [docs/contributor/first-30-minutes.md](docs/contributor/first-30-minutes.md) and [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md) before the full [ARCHITECTURE.md](ARCHITECTURE.md).

## Repo map

| Area | Primary responsibility | Start here |
| --- | --- | --- |
| CLI and operator commands | User-facing flows, status, doctor, install, explain | `cmd/sir/` |
| Hook mediation and security checks | Tool classification, hook evaluation, lifecycle guards | `pkg/hooks/` |
| Session and runtime state | Durable session state, lineage, runtime descriptors, compatibility | `pkg/session/` |
| Ledger integrity | Append-only audit history and hash-chain verification | `pkg/ledger/` |
| MCP inventory and rewrite | MCP inventory, rewrite flows, and proxy-aware config shaping | `pkg/mcp/` |
| Runtime containment | `sir run`, local proxy policy, Linux/macOS containment | `pkg/runtime/` |
| Telemetry and health | OTLP export, queue health, dropped-event visibility | `pkg/telemetry/` |
| Agent adapters | Claude, Codex, Gemini adapter contracts and support metadata | `pkg/agent/` |
| Rust policy oracle | Final lease-bound verdicts and IFC flow checks | `mister-core/src/` |

If your diff spans more than one row, split the change or be explicit in the PR about which subsystem owns the behavior.

## Change lanes

Safe first changes:

- **Runtime status or recovery messaging** — `cmd/sir/status*.go`, `cmd/sir/doctor.go`, `cmd/sir/operability.go`.
- **Hook decision copy and alerts** — `pkg/hooks/messages/`, `pkg/hooks/messages.go`.
- **Hook lifecycle and session handling** — `pkg/hooks/lifecycle/`, `pkg/session/runtime*.go`.
- **Invariant fixtures and contributor docs** — `cmd/sir/security_invariants*_test.go`, `testdata/security-invariants/`, `docs/contributor/`.

Good first security changes:

- Add or tighten runtime/operability tests before changing behavior.
- Add invariant fixtures for a new security claim before editing enforcement logic.
- Improve denial or ask copy only when the underlying policy already exists.
- Split helpers by concern when a file is mixing detection, persistence, and operator output.

## Visible backlog

Keep public work legible on the `sir roadmap` board. Backlog issues should land in exactly one track:

| Track | Scope | Validation | Likely files |
| --- | --- | --- | --- |
| `public-contract` | Docs, workflows, or contract tests drifted and need to line back up. | `make public-contract` | `README.md`, `docs/`, `cmd/sir/public_contract_test.go` |
| `install-onboarding-parity` | Install, auto-detect, or first-run behavior diverged across agents. | `go test ./cmd/sir ./pkg/agent` | `install.sh`, `cmd/sir/install*.go`, `pkg/agent/` |
| `runtime-hardening` | `sir run`, proxy policy, or runtime status/doctor visibility needs tightening. | `go test ./pkg/runtime ./pkg/session ./cmd/sir` and `make bench-check` | `pkg/runtime/`, `pkg/session/runtime*.go`, `cmd/sir/status_runtime.go` |
| `adapter-parity` | Claude / Gemini / Codex support claims or behavior need to move closer together without widening guarantees. | `go test ./pkg/agent ./pkg/hooks` | `pkg/agent/`, `docs/user/*support*.md` |
| `hotspot-refactor` | A mixed-concern file needs a behavior-preserving split plus tests. | Touched package tests plus `go test ./...` | Whichever subsystem hotspot the issue names |

> **Note:** `good-first-security-change` is a contributor-fit label, not a track. Use it for bounded security improvements that a new contributor can land safely in one branch. Keep GitHub's `good first issue` label in sync when the issue is suitable for broader newcomer discovery.

Issue shape for these tracks:

- **Problem** — what drift, risk, or contributor pain exists now.
- **Smallest acceptable scope** — the narrowest change that still counts as done.
- **Validation** — the exact commands expected before merge.
- **Starter files** — the first two to five files a contributor should read.

Backlog labels are synced automatically from the backlog issue form. Maintainers should keep these labels visible and current:

- `public-contract`
- `install-onboarding-parity`
- `runtime-hardening`
- `adapter-parity`
- `hotspot-refactor`
- `good-first-security-change`

Open an issue first or pull in a maintainer when changing:

- lease format, runtime descriptor shape, or session compatibility behavior
- MSTR bridge framing or Rust policy verdict semantics
- containment enforcement boundaries in `pkg/runtime/`
- support tiers, agent capability claims, or public security guarantees

High-risk change lanes:

- `pkg/runtime/` — host-agent boundary changes, destination policy, or degraded-mode semantics.
- `pkg/core/` — Go/Rust bridge framing, fallback semantics, or final verdict shaping.
- `pkg/session/` — schema compatibility, lock behavior, runtime descriptor evolution, or lineage persistence.
- `pkg/hooks/` — new deny/ask paths, tamper handling, or lifecycle behavior that can widen enforcement.

Useful docs:

- [docs/contributor/security-engineering-core.md](docs/contributor/security-engineering-core.md)
- [docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md)
- [CONTRIBUTING-AGENTS.md](CONTRIBUTING-AGENTS.md)
- [docs/README.md](docs/README.md)

## Non-negotiables

These rules are load-bearing for the security model. Changes that relax them need a maintainer conversation first.

- Go stays standard-library only unless there is a reviewed exception. A third-party dependency in the hook path is a new way for an attacker to reach sir.
- `mister-core` and `mister-shared` stay zero-dependency and zero-unsafe. The policy oracle has to be small enough to read in one sitting.
- Go may add restrictions from facts Rust cannot see. It must never widen a Rust deny. Parity is enforced by `TestLocalEvaluate_VerbParity` and `TestEnforcementGradientDocParity`.
- Corrupted or unreadable state fails closed. Only `os.IsNotExist` may seed fresh defaults; everything else becomes a guard deny.
- Path-sensitive checks must resolve symlinks before classification.
- The ledger and telemetry never store raw secrets — only hashes, verbs, and verdicts.
- Public claims need executable coverage: tests, fixtures, or contract checks. If a behavior cannot be expressed in one of those, it is not stable enough to trust.

## Verification

Run this while iterating:

```bash
go test ./...
cargo test --locked
make replay
```

Run these when the change touches docs, versions, hot paths, or security invariants:

```bash
make public-contract
make bench-check
go test ./cmd/sir -run TestSecurityInvariantSuiteV1
```

Use `make bench` when you touch hook evaluation, ledger verification, session mutation, runtime bookkeeping, or `sir explain`.

## Pull requests

1. Keep the diff scoped to one behavior change.
2. Add or update tests before changing security-sensitive behavior.
3. Update docs only when the public or contributor contract changed.
4. Re-run the matching checks and include them in the PR body.

Review checklist for runtime, core, and session changes:

- The change does not widen a Rust deny or silently downgrade enforcement.
- Compatibility for older session, runtime, or ledger state is either preserved or explicitly migrated.
- Status and doctor output explains new degraded or stale states in operator terms.
- The diff includes unit or invariant coverage for the public or security claim it changes.

Open an issue first for protocol changes, lease-format changes, enforcement-gradient changes, or broad new detection categories.

## Conduct and security

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md).

> **Warning:** Do not open public issues for vulnerabilities.

- **Email:** security@somoore.dev
- **GitHub Security Advisories:** use the "Report a vulnerability" button on the Security tab.

See [SECURITY.md](SECURITY.md) for the full reporting policy.
