# sir Supply Chain Policy

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir is a security runtime for AI coding agents. Its whole value proposition — a small, auditable policy oracle that constrains agents from above — collapses the moment the supply chain grows a soft spot. A dependency added in a hurry, an unpinned action, or a mutable release tag would give an attacker a shorter path to sir than the attacks sir is trying to stop.

The supply chain has to stay boring, auditable, and hard to widen by accident. The zero-dependency Rust core and the standard-library-only Go CLI are not aesthetic choices; they are the reason the trust boundary is reviewable at all.

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
- `scripts/check_workflow_policy.rb`, wired through the `actionlint` workflow, enforces the ban on `pull_request_target` and `workflow_run`, so the policy fails closed when workflow files change.
- One deterministic `zizmor` audit must run on workflow changes. The current repo-owned workflow uses explicit offline mode in both PR and `main` workflows, because the hosted token does not have stable GitHub advisories access. If that changes, document the switch back to online coverage.

### Release artifacts are verifiable

Every release ships checksums, signed artifacts, provenance, and SBOM output. Use [docs/research/security-verification-guide.md](../research/security-verification-guide.md) for the operator flow, or run:

```bash
make verify-release RELEASE_TAG=vX.Y.Z
```

## Install and update integrity

The only supported update path is `install.sh` from a vetted tree.

- No auto-updater.
- No background checker.
- No `sir update`.
- Downgrade protection in `install.sh`.
- Controlled rollback via `SIR_ALLOW_DOWNGRADE=1`.

## Branch and release hygiene

- Protection rules on the default branch.
- Required CI before merge.
- Required status checks should only reference pre-merge workflows that always run on PRs and merge queues.
- For the current workflow layout, require the `CI / Rust (mister-core)` and `CI / Go (sir CLI)` checks.
- Treat path-scoped workflows such as `actionlint` and `Performance Guardrails` as non-required unless you move them to rules scoped by matching file paths.
- Do not mark post-merge-only workflows as required branch-protection checks.
- For the current solo-maintainer setup, keep pull requests required but set required approvals to `0`; otherwise self-authored changes deadlock on `last_push_approval` and code-owner review.
- Authenticated maintainer release workflow.
- Release tags must point to commits reachable from `main`.
- GitHub immutable releases stay enabled.
- `v*` tags are protected from mutation or deletion by repository rulesets.
- The `release` environment must disable admin bypass and restrict deployments to release tags only.
- Version alignment between `cmd/sir/version.go`, tags, and `aibom.json`.
- Contributor hygiene enforced with `make contributor-check`.

### Release approval reality check

The target end state is Astral-style separation of duties: required reviewers on the `release` environment, self-review disabled, and a human approval click before publication.

> **Warning:** That last control depends on having at least two trusted maintainers. On a single-maintainer repository, `required_reviewers + prevent_self_review=true` deadlocks releases. Until a second trusted reviewer exists, keep the environment locked down with no admin bypass and restricted deployment refs, and flip self-review prevention on as soon as a second reviewer is available.

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

- Floating toolchain versions.
- Unreviewed Rust dependency additions.
- Tag-based GitHub Actions pins.
- Shipping unsigned or unchecked release artifacts.
- Undocumented widening of the install or release path.
