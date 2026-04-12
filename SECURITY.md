# Security Policy

We take the security of **sir** extremely seriously. A compromised security tool is worse than no security tool at all. If you believe you've found a vulnerability, we want to hear about it and will work with you to resolve it quickly.

## Reporting a Vulnerability

To report a security issue, **[open a GitHub issue](https://github.com/somoore/sir/issues/new)** using the template below.

> **Note:** sir is an experimental, pre-1.0 project. We use public GitHub issues for vulnerability reports to keep the process simple and transparent.

### Disclosure Template

When filing your issue, please include the following:

```
**Title:** [Brief description of the vulnerability]

**What I found:**
[Describe the vulnerability clearly — what component is affected, what the
unexpected behavior is, and what an attacker could achieve.]

**When I found it:**
[Date of discovery]

**Why this is an issue:**
[Explain the security impact — why does this matter? What trust boundary
is violated? What could go wrong in a real deployment?]

**Steps to reproduce:**
1. [Step one]
2. [Step two]
3. [...]

**Self-assessed severity:** [Critical / High / Medium / Low]

- Critical: RCE, secret exfiltration, complete policy bypass
- High: Policy bypass for specific verbs, label evasion, ledger tampering
- Medium: Information disclosure, denial of service, state corruption
- Low: Minor issues, hardening suggestions

**Environment:**
- OS:
- sir version:
- Agent (Claude Code / Codex / Gemini CLI):

**Suggested fix (optional):**
[If you have ideas on how to fix it, we'd love to hear them.]
```

## What Happens Next

1. **We triage** — we review the report, confirm the issue, and assign a severity.
2. **We collaborate** — we work with you (the submitter) to understand the root cause and develop a fix.
3. **We ship** — we release a patched version and credit you in the release notes (unless you prefer to remain anonymous).

## Scope

The following are **in scope** for security reports:

- Policy bypass (actions that should be denied are allowed)
- IFC label evasion (data flows that should be blocked are not)
- Credential or secret exposure through sir itself
- Supply chain attacks on sir's build or distribution
- Tampering with sir's enforcement state (ledger, lease, posture files)
- Privilege escalation through sir's hooks
- Denial of service that degrades sir's protection

The following are **documented v1 limitations**, not vulnerabilities. They are tracked for hardening in future releases:

- Shell command classification is lexical and prefix-based
- MCP injection detection is heuristic regex matching
- IFC labels do not track model-internal reasoning, only observable tool I/O
- The default lease is permissive; hardening is the operator's responsibility

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full v1 tradeoff set.

## Supply Chain Security

sir's supply chain posture is documented in [docs/contributor/supply-chain-policy.md](docs/contributor/supply-chain-policy.md). Key points:

- `mister-core` (Rust) has **zero** external dependencies
- All CI actions are pinned to SHA hashes
- All toolchain versions are pinned
- Release artifacts include SHA-256 and SHA-512 checksums
- `Cargo.lock` and `go.sum` are committed to the repository

## Acknowledgments

We credit security researchers who report valid vulnerabilities in our release notes (unless they prefer to remain anonymous).
