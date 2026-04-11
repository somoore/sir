# Documentation Hub

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir — Sandbox in Reverse — is an experimental security runtime for AI coding agents. It mediates agent tool calls at the hook layer, tracks secret taint through IFC, and writes every decision to a hash-chained ledger. This repo keeps one small active docs surface. Start with the shortest path that matches your job:

- Thesis, install, and first-run walkthrough: [README.md](../README.md)
- Runtime behavior: [docs/user/runtime-security-overview.md](user/runtime-security-overview.md)
- Claude / Gemini / Codex details: [docs/user/claude-code-hooks-integration.md](user/claude-code-hooks-integration.md), [docs/user/gemini-support.md](user/gemini-support.md), [docs/user/codex-support.md](user/codex-support.md)
- Troubleshooting and daily commands: [docs/user/faq.md](user/faq.md)
- Contributor setup, subsystem ownership, and visible backlog tracks: [CONTRIBUTING.md](../CONTRIBUTING.md)
- Fast contributor orientation: [docs/contributor/first-30-minutes.md](contributor/first-30-minutes.md)
- Architecture and invariants: [ARCHITECTURE.md](../ARCHITECTURE.md), [docs/contributor/security-engineering-core.md](contributor/security-engineering-core.md)
- Release verification and threat model: [docs/research/security-verification-guide.md](research/security-verification-guide.md), [docs/research/validation-summary.md](research/validation-summary.md), [docs/research/sir-threat-model.md](research/sir-threat-model.md)
