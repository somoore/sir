# Documentation

> [!NOTE]
> sir is experimental — test on your own machine, not shared infrastructure. `sir doctor` recovers any wedged state; [report bugs](https://github.com/somoore/sir/issues).

Start with the [README](../README.md). Then pick the shortest path for your job.

### Use sir
- [Runtime behavior](user/runtime-security-overview.md) — what sir catches at the boundary, and what it doesn't.
- [FAQ](user/faq.md) — daily commands and troubleshooting.
- Agent setup — [Claude Code](user/claude-code-hooks-integration.md) · [Gemini CLI](user/gemini-support.md) · [Codex](user/codex-support.md).
- [SIEM integration](user/siem-integration.md) — OTLP attributes, detection IDs, and the Slack relay.

### Contribute
- [CONTRIBUTING.md](../CONTRIBUTING.md) — setup, standards, PR process.
- [first-30-minutes](contributor/first-30-minutes.md) — fast orientation.
- [core-mental-model](contributor/core-mental-model.md) · [security-engineering-core](contributor/security-engineering-core.md) — how decisions are made and where the trust boundary sits.
- [ARCHITECTURE.md](../ARCHITECTURE.md) — system design and invariants.

### Verify the claims
- [Threat model](research/sir-threat-model.md) — attacker model and scope.
- [Security verification guide](research/security-verification-guide.md) — reproduce the guarantees.
- [Observability design](research/observability-design.md) — the three-tier (governance / detection / investigation) model.
