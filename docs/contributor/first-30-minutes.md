# First 30 Minutes

Use this path when you are new to the repo and want the shortest safe route to a useful change.

> **Note:** sir is a "sandbox in reverse" — it constrains AI coding agents from above at the hook layer rather than from below at the syscall layer, with a pure Rust policy oracle (`mister-core`) as the upper bound on what is ever allowed, and a Go layer that may only be stricter. sir is experimental. Your first change should fit that boundary: small, test-backed, and never widening what Rust denies.

## 1. Start from clean main

```bash
git fetch origin
git switch -c my-change origin/main
make contributor-check
```

If `make contributor-check` fails, stop there. Fix the branch/worktree problem before you read diffs or change security code.

## 2. Pick one bounded backlog issue

Start from a public issue labeled `good-first-security-change` or one of the named backlog labels in [CONTRIBUTING.md](../../CONTRIBUTING.md). The backlog issue form applies the track labels automatically.

Safe first examples in this repo:

- Add a public-contract assertion for a contributor or runtime doc guarantee.
- Tighten a runtime status or doctor receipt test without widening containment claims.
- Add an install or adapter-parity regression test.
- Split a helper that mixes persistence and operator output without changing behavior.
- Turn a confirmed bug into a follow-up backlog issue with starter files and validation commands.

## 3. Read only two files first

- [Core Mental Model](core-mental-model.md) — the trust boundaries and Go/Rust split in one short pass.
- [CONTRIBUTING.md](../../CONTRIBUTING.md) — the repo workflow and required verification commands.

After that, read one subsystem file that matches the change you want to make. If the change touches hook behavior, start with [pkg/hooks/doc.go](../../pkg/hooks/doc.go) before you open the individual hook files.

## 4. Run the core verification loop

```bash
go test ./...
cargo test --locked
make replay
```

If you are touching hook evaluation, session state, ledger verification, or `sir explain`, also run:

```bash
make bench
```

## 5. Pick a safe entry point

| Change type | Start here | Why |
| --- | --- | --- |
| New shell command prefix or classifier fix | [pkg/hooks/toolmap.go](../../pkg/hooks/toolmap.go) and [pkg/hooks/toolmap_shell.go](../../pkg/hooks/toolmap_shell.go) | Tool intent mapping lives here |
| Sensitive-path or IFC-label update | [pkg/hooks/labels.go](../../pkg/hooks/labels.go) | Path-based labeling starts here |
| User-facing approval/block copy | [pkg/hooks/messages.go](../../pkg/hooks/messages.go) and siblings | Messaging is centralized here |
| Agent adapter change | [pkg/agent/](../../pkg/agent/) and [CONTRIBUTING-AGENTS.md](../../CONTRIBUTING-AGENTS.md) | Agent-specific hook behavior lives here |
| Policy-rule change | [mister-core/src/policy.rs](../../mister-core/src/policy.rs) and [pkg/policy/surface_gen.go](../../pkg/policy/surface_gen.go) | Rust owns normalized policy; Go adds preflight/session gates and mirrors the typed surface |
| Session / lineage / posture state | [pkg/session/](../../pkg/session/) | Secret-session, managed-mode, and runtime state are here |
| Runtime containment | [cmd/sir/doc.go](../../cmd/sir/doc.go), [pkg/runtime/](../../pkg/runtime/), and [ARCHITECTURE.md](../../ARCHITECTURE.md) | Host-agent containment lives below the CLI in a reusable runtime package |

## 6. Choose a first change that stays bounded

Good first repo-local contributions:

- Add or fix a shell classifier.
- Tighten a docs or public-contract guarantee.
- Add or improve a hook fixture.
- Improve a user-facing approval or block message.
- Add regression coverage around session, ledger, or `explain` behavior.

Avoid these until you already understand the repo seams:

- Changing the MSTR/1 protocol.
- Widening or narrowing policy behavior in Rust without adding tests.
- Changing managed-mode semantics.
- Changing runtime containment guarantees in docs without matching tests.

## 7. Open the right supporting docs

- [Security Engineering Core](security-engineering-core.md)
- [ARCHITECTURE.md](../../ARCHITECTURE.md)
- [pkg/hooks package guide](../../pkg/hooks/doc.go)
- [CHANGELOG.md](../../CHANGELOG.md)
- [docs/README.md](../README.md)
