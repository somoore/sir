# sir Supply Chain Policy

sir is a security tool. The supply chain has to stay boring, auditable, and hard to widen by accident.

## Hard requirements

### Rust stays zero-dependency

- `mister-core` and `mister-shared` may only depend on workspace crates.
- `Cargo.lock` must contain exactly two packages.
- `cargo-deny` enforces sources, licenses, and bans in CI.

### Toolchains are pinned

| Toolchain | Version | Source of truth |
| --- | --- | --- |
| Rust | 1.94.0 | `rust-toolchain.toml` |
| Go | 1.22 minimum / 1.25.9 toolchain | `go.mod` |

CI, `Makefile`, and `install.sh` must match those pins.

### CI stays hardened

- GitHub Actions are pinned by full SHA.
- GitHub enforces SHA-pinned actions and an explicit allowlist for every external action and reusable workflow.
- Workflows default to `permissions: {}`.
- `persist-credentials: false` is used on checkout.
- Builds are reproducible: `CARGO_INCREMENTAL=0`, `CGO_ENABLED=0`, `-trimpath`, and stripped release binaries.
- `govulncheck`, `gosec`, and `cargo-deny` run in CI.
- Required pre-merge CI stays lean: Linux Rust and Linux Go validation only.
- Post-merge assurance on `main` owns the expensive checks: reproducibility, artifact packaging, checksums, SBOM generation, and macOS validation.
- Merge queue support must stay enabled on required pre-merge workflows.
- `pull_request_target` and `workflow_run` stay banned for CI/CD. If the project ever needs privileged PR or issue automation, use a GitHub App instead of a privileged workflow trigger.
- `actionlint` enforces the ban on `pull_request_target` and `workflow_run` so the policy fails closed when workflow files change.
- One online `zizmor` audit must run outside the PR fast path so `known-vulnerable-actions` coverage is restored without making contributor CI flaky.

### Release artifacts are verifiable

Every release ships checksums, signed artifacts, provenance, and SBOM output.
Use [docs/research/security-verification-guide.md](../research/security-verification-guide.md)
for the operator flow, or run:

```bash
make verify-release RELEASE_TAG=vX.Y.Z
```

## Install and update integrity

The only supported update path is `install.sh` from a vetted tree.

- no auto-updater
- no background checker
- no `sir update`
- downgrade protection in `install.sh`
- controlled rollback via `SIR_ALLOW_DOWNGRADE=1`

## Branch and release hygiene

- protection rules on the default branch
- required CI before merge
- required status checks should only reference pre-merge workflows that always run on PRs and merge queues
- for the current workflow layout, require the `CI / Rust (mister-core)` and `CI / Go (sir CLI)` checks
- treat path-scoped workflows such as `actionlint` and `Performance Guardrails` as non-required unless you move them to rules scoped by matching file paths
- do not mark post-merge-only workflows as required branch-protection checks
- for the current solo-maintainer setup, keep pull requests required but set required approvals to `0`; otherwise self-authored changes deadlock on `last_push_approval` and code-owner review
- authenticated maintainer release workflow
- release tags must point to commits reachable from `main`
- GitHub immutable releases stay enabled
- `v*` tags are protected from mutation or deletion by repository rulesets
- the `release` environment must disable admin bypass and restrict deployments to release tags only
- version alignment between `cmd/sir/version.go`, tags, and `aibom.json`
- contributor hygiene enforced with `make contributor-check`

### Release approval reality check

The target end state is Astral-style separation of duties: required reviewers on
the `release` environment, self-review disabled, and a human approval click
before publication.

That last control depends on having at least two trusted maintainers. On a
single-maintainer repository, `required_reviewers + prevent_self_review=true`
deadlocks releases. Until a second trusted reviewer exists, keep the
environment locked down with no admin bypass and restricted deployment refs, and
flip self-review prevention on as soon as a second reviewer is available.

## Local verification

Run this before a release PR:

```bash
go test ./...
cargo test --locked
make public-contract
make replay
make bench-check
make verify-release RELEASE_TAG=vX.Y.Z
```

## Things we do not relax

- floating toolchain versions
- unreviewed Rust dependency additions
- tag-based GitHub Actions pins
- shipping unsigned or unchecked release artifacts
- undocumented widening of the install or release path
