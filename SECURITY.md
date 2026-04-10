# Security Policy

sir is a security tool. We take vulnerabilities in sir extremely seriously --- a compromised security tool is worse than no security tool.

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities via email:

- **Email:** security@somoore.dev
- **Subject prefix:** `[sir-VULN]`
- **Include:**
  - Description of the vulnerability
  - Steps to reproduce
  - Impact assessment
  - Suggested fix (if any)

## Response SLA

| Severity | Acknowledgment | Fix Target |
|----------|---------------|------------|
| Critical (RCE, auth bypass, secret leak) | 24 hours | 72 hours |
| High (policy bypass, label evasion) | 48 hours | 1 week |
| Medium (information disclosure, DoS) | 1 week | 2 weeks |
| Low (minor issues) | 2 weeks | Next release |

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (current) | Yes |

We will backport critical fixes to the latest release only. Earlier versions are not supported.

## Security Update Process

1. Vulnerability is reported via the email above.
2. We confirm receipt within the acknowledgment SLA.
3. We investigate and develop a fix in a private branch.
4. We coordinate disclosure timing with the reporter.
5. We release a patched version with a security advisory.
6. We publish a GitHub Security Advisory (GHSA).

## Scope

The following are in scope for security reports:

- Policy bypass (actions that should be denied are allowed)
- IFC label evasion (data flows that should be blocked are not)
- Credential or secret exposure through sir itself
- Supply chain attacks on sir's build or distribution
- Tampering with sir's enforcement state (ledger, lease, posture files)
- Privilege escalation through sir's hooks
- Denial of service that degrades sir's protection

The following are documented limitations, not vulnerabilities:

- Shell command classification is prefix-based (documented in CLAUDE.md)
- IFC labels do not track model-internal reasoning (documented)
- Session secret flag is coarse-grained (documented)
- `approved_remotes` defaults to `["origin"]` as a heuristic (documented)

## Supply Chain Security

sir's supply chain posture is documented in `docs/contributor/supply-chain-policy.md`. Key points:

- mister-core (Rust) has **zero** external dependencies
- All CI actions are pinned to SHA hashes
- All toolchain versions are pinned
- Release artifacts include SHA-256 and SHA-512 checksums
- Cargo.lock and go.sum are committed to the repository

## Acknowledgments

We will credit security researchers who report valid vulnerabilities (unless they prefer to remain anonymous) in our release notes and this file.
