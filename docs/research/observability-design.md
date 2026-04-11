# Observability Design — sir and the Three-Tier Model

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

Security researcher Zack Korman has published a public critique of AI coding agent observability that separates three tiers of value: **governance** (checkbox compliance — "we have logs"), **investigation** (backward-looking — "we can reconstruct what happened"), and **detection** (real-time — "we catch bad things as they happen"). His core finding is that every major AI coding agent provider stops at tier 1. Provider audit logs capture the user prompt and which tools ran, but not tool response content, not MCP arguments, and not the reasoning chain — so an investigator cannot reconstruct why an agent introduced a vulnerability, and a detector cannot catch a malicious MCP response because the response text was never logged. See Korman's writing under [github.com/zkorman](https://github.com/zkorman) for the source of the three-tier framing used here.

sir is architected for all three tiers at the tool-call boundary. This document lays out how each tier is wired, which code paths are load-bearing, and where sir intentionally does *not* try to help.

## Tier 3 — detection

sir enforces at two distinct moments. PreToolUse decisions run *before* the tool executes and can block or ask for approval. PostToolUse and lifecycle checks run *immediately after* the tool returns, before the agent processes the output, and can raise posture, taint the session, or deny the next call. Both moments feed the same ledger and the same alert taxonomy.

- **Per-path lineage for writes and commits.** A credential read attaches a derived-lineage label to the specific paths the agent writes, commits, or pushes from. The lattice that carries the labels is [`mister-core/src/ifc.rs`](../../mister-core/src/ifc.rs); the Go side tracks lineage in [`pkg/session/lineage.go`](../../pkg/session/lineage.go) and feeds it into policy at [`pkg/hooks/lineage.go`](../../pkg/hooks/lineage.go). A write from a secret-derived file is gated at `stage_write`, `commit`, and `push_*` — not every later write in the session.
- **Turn-scoped secret-session egress gating.** Separately from per-path lineage, reading a credential file raises a turn-scoped `secret_session` flag that gates external network egress and push verbs for the rest of the turn. The Rust side enforces it in [`mister-core/src/policy_guards.rs`](../../mister-core/src/policy_guards.rs); the flag is cleared on the next turn boundary or by `sir unlock` (see [`pkg/session/session_turns.go`](../../pkg/session/session_turns.go)). The two mechanisms are orthogonal: lineage gates "did the data *derive* from a secret", session gates "is this turn *carrying* secret context at all".
- **MCP argument scanning (pre-tool).** Before an MCP tool call ships, sir walks the arguments for credential patterns and denies the call when a match fires *on untrusted servers*. Servers explicitly approved via `sir trust` are exempted from the scan. The preflight helper is [`pkg/hooks/evaluate_preflight.go`](../../pkg/hooks/evaluate_preflight.go); the scanner lives in [`pkg/secretscan`](../../pkg/secretscan).
- **MCP response scanning (post-tool, pre-processing).** Injection markers in MCP responses trigger a posture raise, a tainted-server flag, and a pending injection alert in [`pkg/hooks/post_evaluate_analysis.go`](../../pkg/hooks/post_evaluate_analysis.go). This runs after the tool returned output but before the agent acts on it — the next PreToolUse intercepts and requires developer re-approval.
- **Posture tamper (post-tool + lifecycle).** Changes to the hook config, `CLAUDE.md`, or `.mcp.json` are detected on PostToolUse and on `ConfigChange` / lifecycle events. The detection paths write a `hook_tamper` alert with an explicit `AlertType` so downstream SIEM filters do not have to parse reason strings. See [`pkg/hooks/config_change.go`](../../pkg/hooks/config_change.go) and [`pkg/hooks/post_evaluate_checks.go`](../../pkg/hooks/post_evaluate_checks.go).

A traditional sandbox cannot express any of these because the interesting condition is the agent's *intent* across a sequence of tool calls, not a single syscall.

## Tier 2 — investigation

sir records enough evidence for an investigator to reconstruct what happened, without ever persisting raw secrets.

- **Redacted evidence on alerts.** When a credential or injection alert fires, the ledger entry carries a redacted copy of the triggering payload. Tool output is routed through [`ledger.RedactContent`](../../pkg/ledger/redact.go); MCP JSON arguments are routed through `RedactMapValues` + `TruncateToWordBoundary` (see [`pkg/hooks/evidence/evidence.go`](../../pkg/hooks/evidence/evidence.go)). Known credential patterns are replaced with `[REDACTED:<class>]` markers. The same redaction fires twice — once when the ledger store writes the line and again in the telemetry exporter ([`pkg/telemetry/otlp_redact.go`](../../pkg/telemetry/otlp_redact.go)) — so a refactor that skips one path still cannot leak content.
- **Redacted evidence on clean allow paths.** Korman's sharpest critique was that "nothing happened" logs cannot answer the investigator's question. sir closes that gap with the `tool_trace` ledger entry, written for every allow-path PostToolUse call when `SIR_LOG_TOOL_CONTENT=1` is set. The helper is [`applyPostEvaluateAllowTrace`](../../pkg/hooks/post_evaluate_trace.go) and the constructor lives at [`pkg/hooks/internal/postflight/alerts.go`](../../pkg/hooks/internal/postflight/alerts.go). Dedup is explicit: when an alert entry already carries the redacted evidence, the trace write is suppressed — the alert is authoritative, the trace is additive.
- **Sensitive target hashing.** When a clean allow-path read touches a sensitive file (`~/.aws/credentials`, a `.env`, a PEM), the trace entry is marked `Sensitivity="secret"` so [`telemetry.RedactTarget`](../../pkg/telemetry/otlp_redact.go) sha256-hashes the path before OTLP emission. Raw sensitive paths never leave the host even on clean reads. The regression test lives at [`pkg/hooks/evidence_test.go`](../../pkg/hooks/evidence_test.go) (`TestPostEvaluate_AllowTraceMarksSensitiveTarget`).
- **Hash-chained ledger.** Every entry is appended with `prev_hash`, `entry_hash`, and a monotonic index. `sir log verify` walks the chain and reports the first corruption. The ledger is the authoritative local record an investigator trusts when provider logs run out.
- **`sir explain --last`.** The explain formatter surfaces the redacted evidence block for any ledger entry that carries it, alert or trace. See [`cmd/sir/explain.go`](../../cmd/sir/explain.go).

Evidence logging is opt-in by design. Setting `SIR_LOG_TOOL_CONTENT=1` is a deliberate operator choice that trades a larger ledger for full tier-2 reconstruction. Without the flag, sir is silent on clean tool calls — the pre-existing privacy default.

## Tier 1 — governance

When `SIR_OTLP_ENDPOINT` is set, the policy-decision code paths emit their ledger entries to an operator-controlled SIEM collector via OTLP/HTTP JSON. The exporter uses only the Go standard library, never calls home, and redacts every attribute before serialization. The full attribute taxonomy and the query examples live in [`docs/user/siem-integration.md`](../user/siem-integration.md). The short version:

- `sir.ledger.index` and `sir.ledger.hash` give the SIEM a chain-of-custody signal without shipping the raw ledger file.
- `sir.alert.type` carries the alert taxonomy (`credential_in_output`, `mcp_credential`, `mcp_injection`, `hook_tamper`, `sentinel_mutation`, `config_change_posture`, `posture_change`, `posture_change_session_end`, `elicitation_harvesting`) so a governance query can count alerts by class without parsing reason strings.
- `sir.evidence` is populated only when `SIR_LOG_TOOL_CONTENT=1` is set, and carries the double-redacted content.
- `sir.session.secret`, `sir.posture.state`, `sir.posture.mcp_taint`, and `sir.posture.injection_alert` give the SIEM enough context to distinguish "routine allow" from "allow under tainted posture" without re-deriving state.

Not every ledger append site is wired into the exporter. Hook-lifecycle telemetry (PreToolUse / PostToolUse / hook-tamper / credential / injection / sentinel-mutation) is emitted; a few non-hook append sites — session-summary rollups, CLI allowlist changes, and some config-change bookkeeping — are recorded in the local ledger but not in the OTLP stream. When a compliance dashboard needs 100% coverage, the authoritative source is the local hash-chained ledger file, with OTLP as the live-tailing fan-out.

## Why evidence is opt-in

Three reasons:

1. **Default privacy.** Most sir users are individual developers. A silent ledger is the right default for "I just want sir to block dangerous things." Evidence logging materializes investigation state on disk and ships it to a collector — that needs an explicit operator decision, not a default.
2. **Ledger size.** A long Claude Code session can make hundreds of tool calls. `SIR_LOG_TOOL_CONTENT=1` turns every one of those into a ledger entry. For small projects that is fine; for teams with retention policies that needs to be an opt-in they sized.
3. **Defense in depth.** Making it a deliberate opt-in means a compromise of the env variable alone does not cause tier-2 evidence to appear where it should not. The ledger redaction path is still mandatory in either mode — there is no configuration that persists raw secrets. The env var controls only whether the `Evidence` field is populated at all.

## Out of scope: model-internal reasoning

sir is a **boundary runtime** by design. It does not capture the agent's chain-of-thought, internal scratchpad, or reasoning tokens. The [AIBOM](../../aibom.json) declares sir as zero-AI/ML: no models, no weights, no training data, no prompts, no inference, and no data flow *into* an LLM. The optional OTLP exporter may ship redacted ledger-derived telemetry to an operator-controlled SIEM collector, but never to a model provider — that separation is what "zero-ML boundary runtime" means in the AIBOM, and the redaction guarantees in Tier 2 are what make it safe.

Korman's critique covers model-internal observability separately, and the answer there is not a local runtime — it is provider telemetry, model-card transparency, and constitutional auditing. sir is orthogonal to that layer and stays that way intentionally.

## Where to read next

- Operator-facing attribute reference and SIEM queries: [docs/user/siem-integration.md](../user/siem-integration.md)
- Threat model and trust assumptions behind the tiers: [docs/research/sir-threat-model.md](sir-threat-model.md)
- Runtime behavior at the boundary: [docs/user/runtime-security-overview.md](../user/runtime-security-overview.md)
- Verification paths: [docs/research/security-verification-guide.md](security-verification-guide.md)
