# sir Architecture

If you want the shortest path first, read [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md).

## 1. Core thesis

sir is a "sandbox in reverse."

The agent does not inherit authority just because the host tool exposes a
filesystem, shell, network, or delegation surface. It gets authority only when
the current lease and runtime boundary explicitly grant it.

That shows up in three ways:

- lease policy decides what the agent is allowed to do
- hook mediation classifies and enriches what the agent is trying to do
- runtime containment tries to keep the host agent inside a narrower OS/runtime boundary even when hooks are incomplete

## 2. System shape

### `mister-core` (Rust)

Pure policy oracle.

- no filesystem access
- no network access
- no external Rust dependencies
- evaluates normalized requests and returns `allow`, `deny`, or `ask`

### `sir` (Go)

Operator CLI, hook handlers, state, telemetry, ledger, and runtime containment.

- parses hook payloads from supported agents
- classifies tools into normalized intents
- assigns IFC labels and session-level facts
- persists ledger, session, lineage, and runtime state
- calls `mister-core` over the MSTR/1 subprocess boundary

## 3. Enforcement layers

### Lease and policy

`mister-core` owns verb semantics, IFC flow checks, risk tiers, and the final
lease-boundary verdict.

Start here when changing:

- verb rules
- IFC joins and sink checks
- allow/deny/ask gradient
- policy receipts

### Hook mediation

`pkg/hooks` owns fact collection around the host agent's hook surface.

Start here when changing:

- shell and tool classification
- MCP argument and response scanning
- evidence capture and redaction
- session-fatal posture behavior

### Posture and managed restore

`pkg/posture` owns posture hashing, managed hook subtree drift detection, and
hook restore logic.

Start here when changing:

- hook tamper detection
- managed hook subtree hashing
- posture-file baseline comparison
- restore-only hook repair

### Runtime containment

`pkg/runtime` sits below hooks.

Start here when changing:

- `sir run`
- runtime proxy allowlists
- runtime state descriptors
- host-agent containment claims

## 4. State objects that matter

- lease: the authority contract
- session: mutable posture, secret session, lineage, and runtime state
- ledger: append-only decision history
- runtime descriptor: active containment metadata for `sir run`

If a change mutates one of these, add or update tests first.

## 5. One non-negotiable boundary rule

Go may be stricter than Rust. It must never be looser.

Examples of Go-only restrictions:

- deny-all after posture tamper
- MCP credential and injection detections
- managed-mode local command refusal
- runtime containment guardrails

Those may narrow a decision further. They must never widen a Rust `deny` into
`ask` or `allow`.

## 6. Contributor reading order

1. [docs/contributor/core-mental-model.md](docs/contributor/core-mental-model.md)
2. [docs/contributor/security-engineering-core.md](docs/contributor/security-engineering-core.md)
3. [pkg/hooks/doc.go](pkg/hooks/doc.go)
4. [cmd/sir/doc.go](cmd/sir/doc.go)
5. [docs/research/security-verification-guide.md](docs/research/security-verification-guide.md) for the highest-signal verification flow

## 7. Proof surface

The architecture is only real if the repo keeps proving it:

- unit and integration tests
- fixture replay in `testdata/`
- benchmark budgets
- security invariants
- public-contract checks

If a claimed behavior cannot be expressed in one of those surfaces, it is not
stable enough to trust.
