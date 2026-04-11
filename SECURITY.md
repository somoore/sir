# Security Policy

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir is an experimental security runtime for AI coding agents. It constrains agents from above at the hook layer rather than from below at the syscall layer, and its v1 tradeoffs — heuristic MCP injection detection, lexical shell classification, a 30-second turn heuristic, and a deliberately permissive default lease — are documented in [ARCHITECTURE.md](ARCHITECTURE.md) and the contributor docs. Treat sir as a defense-in-depth layer, not an absolute boundary.

That said, we take vulnerabilities in sir extremely seriously. A compromised security tool is worse than no security tool, and any path that lets an attacker widen a Rust `deny` or exfiltrate state from the ledger is a hard bug, not a tradeoff.

## Reporting a vulnerability

> **Warning:** Do not open a public GitHub issue for security vulnerabilities.

Report vulnerabilities via email:

- **Email:** security@somoore.dev
- **Subject prefix:** `[sir-VULN]`
- **Include:**
  - Description of the vulnerability.
  - Steps to reproduce.
  - Impact assessment.
  - Suggested fix (if any).

## Response SLA

| Severity | Acknowledgment | Fix target |
| --- | --- | --- |
| Critical (RCE, auth bypass, secret leak) | 24 hours | 72 hours |
| High (policy bypass, label evasion) | 48 hours | 1 week |
| Medium (information disclosure, DoS) | 1 week | 2 weeks |
| Low (minor issues) | 2 weeks | Next release |

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (current) | Yes |

We will backport critical fixes to the latest release only. Earlier versions are not supported.

## Security update process

1. Vulnerability is reported via the email above.
2. We confirm receipt within the acknowledgment SLA.
3. We investigate and develop a fix in a private branch.
4. We coordinate disclosure timing with the reporter.
5. We release a patched version with a security advisory.
6. We publish a GitHub Security Advisory (GHSA).

## Scope

The following are in scope for security reports:

- Policy bypass (actions that should be denied are allowed).
- IFC label evasion (data flows that should be blocked are not).
- Credential or secret exposure through sir itself.
- Supply chain attacks on sir's build or distribution.
- Tampering with sir's enforcement state (ledger, lease, posture files).
- Privilege escalation through sir's hooks.
- Denial of service that degrades sir's protection.

The following are documented limitations, not vulnerabilities. They are part of the v1 tradeoff set and are tracked for v2 hardening:

- Shell command classification is lexical and prefix-based (documented in `CLAUDE.md` and `ARCHITECTURE.md`).
- MCP injection detection is heuristic regex matching, not a model-backed classifier.
- IFC labels do not track model-internal reasoning, only observable tool I/O.
- The session secret flag is coarse-grained and turn-scoped by default.
- `approved_remotes` defaults to `["origin"]` as a developer-friction heuristic.
- Turn boundaries use a 30-second gap heuristic.
- The default lease is permissive; hardening is the operator's responsibility.

## Supply chain security

sir's supply chain posture is documented in [docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md). Key points:

- `mister-core` (Rust) has **zero** external dependencies.
- `main` accepts changes through pull requests gated by signed commits and required CI checks.
- Release tags (`v*`) are immutable, and GitHub releases are approval-gated through the `release` environment.
- All CI actions are pinned to SHA hashes.
- All toolchain versions are pinned.
- Release artifacts include SHA-256 and SHA-512 checksums.
- `Cargo.lock` and `go.sum` are committed to the repository.

## Acknowledgments

We will credit security researchers who report valid vulnerabilities (unless they prefer to remain anonymous) in our release notes and this file.
