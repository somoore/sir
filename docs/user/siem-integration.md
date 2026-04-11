# SIEM Integration — OTLP Attribute Reference

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir emits every ledger entry to an operator-controlled SIEM collector via OTLP/HTTP JSON when the `SIR_OTLP_ENDPOINT` environment variable points at a reachable URL. The exporter uses only the Go standard library, never calls home, and redacts every attribute before serialization. This page documents the attribute names, the redaction rules, and how to write SIEM queries that answer Zack Korman's three-tier observability questions.

- Where the exporter lives: [`pkg/telemetry/otlp_payload.go`](../../pkg/telemetry/otlp_payload.go)
- Where attributes are redacted: [`pkg/telemetry/otlp_redact.go`](../../pkg/telemetry/otlp_redact.go)
- Where evidence is produced: [`pkg/hooks/post_evaluate_trace.go`](../../pkg/hooks/post_evaluate_trace.go) and [`pkg/hooks/internal/postflight/alerts.go`](../../pkg/hooks/internal/postflight/alerts.go)

## Activation

Set the endpoint once per shell. sir does nothing else until the variable is present:

```bash
export SIR_OTLP_ENDPOINT="https://collector.internal.example/v1/logs"
```

Evidence content (tool response bodies, MCP arguments) is a second, independent opt-in. Set `SIR_LOG_TOOL_CONTENT=1` to populate `sir.evidence` on ledger entries that have content to log. When the variable is unset, `sir.evidence` is absent from every attribute set and the ledger is quiet on clean tool calls. That is the intended privacy default.

```bash
export SIR_LOG_TOOL_CONTENT=1
```

## Attribute reference

sir uses the `sir.*` namespace so the attributes compose cleanly with OTLP resource attributes and with non-sir logs on the same collector.

| Attribute                     | When present                             | Redaction                                                                       |
|-------------------------------|------------------------------------------|---------------------------------------------------------------------------------|
| `sir.tool_name`               | every entry                              | passthrough                                                                     |
| `sir.verb`                    | every entry                              | passthrough                                                                     |
| `sir.verdict`                 | every entry                              | `allow` / `deny` / `ask`                                                        |
| `sir.target`                  | when entry has a target                  | sha256 hash when `sir.ifc.sensitivity="secret"`, hostname-only for network verbs |
| `sir.reason`                  | every entry                              | `ledger.RedactString` removes known credential patterns                         |
| `sir.ifc.sensitivity`         | when IFC labeled                         | `secret` / `untrusted` / ...                                                    |
| `sir.ifc.trust`               | when IFC labeled                         | passthrough                                                                     |
| `sir.ifc.provenance`          | when IFC labeled                         | passthrough                                                                     |
| `sir.posture.state`           | every entry                              | passthrough                                                                     |
| `sir.posture.injection_alert` | when a pending injection alert exists    | boolean                                                                         |
| `sir.posture.mcp_taint`       | when any MCP server is tainted           | boolean                                                                         |
| `sir.session.secret`          | when the session holds secret-labeled data | boolean                                                                         |
| `sir.ledger.index`            | every entry                              | monotonic integer                                                               |
| `sir.ledger.hash`             | every entry                              | sha256 hex, covers the full line                                                |
| `sir.alert.type`              | alert entries                            | e.g. `credential_in_output`, `mcp_credential_leak`, `mcp_injection`, `hook_tamper`, `sentinel_mutation` |
| `sir.alert.severity`          | alert entries                            | `HIGH` / `MEDIUM` / `LOW`                                                       |
| `sir.alert.agent.id`          | hook-tamper entries                      | `claude` / `gemini` / `codex`                                                   |
| `sir.alert.diff_summary`      | posture alerts                           | `ledger.RedactString` applied                                                   |
| `sir.alert.restored`          | hook-tamper entries                      | boolean — whether auto-restore succeeded                                        |
| `sir.evidence`                | when `SIR_LOG_TOOL_CONTENT=1` is set     | `ledger.RedactContent` replaces credentials with `[REDACTED:<class>]` markers, truncated to 1024 bytes for tool output and 2048 bytes for MCP JSON arguments |

Redaction fires twice on the evidence field — once when the ledger store writes the line, and once again in the telemetry exporter — so a future refactor that skips one path still cannot export raw credential content.

## Example queries

sir ships three observability tiers. These queries answer one question per tier.

### Tier 3 — detection (alerts in real time)

Find every alert entry in the last hour, filtered to the noisiest alert types:

```sql
sir.alert.type IN ("credential_in_output", "mcp_credential_leak", "mcp_injection", "hook_tamper")
  AND @timestamp >= now - 1h
| stats count by sir.alert.type, sir.tool_name
```

### Tier 2 — investigation (reconstruct what happened)

Find every MCP credential leak where the redacted payload survived the exporter, so you can drill into what was about to be sent:

```sql
sir.verb = "mcp_credential_leak"
  AND sir.evidence IS NOT NULL
| table @timestamp, sir.tool_name, sir.target, sir.evidence
```

sir writes a `tool_trace` ledger entry for every clean allow-path tool call when `SIR_LOG_TOOL_CONTENT=1`. That is the entry type to query when investigating "what did the agent actually read" after the fact:

```sql
sir.verb = "tool_trace"
  AND sir.verdict = "allow"
  AND sir.session.secret = true
| table @timestamp, sir.tool_name, sir.target, sir.evidence
```

### Governance — chain-of-custody

The `sir.ledger.index` and `sir.ledger.hash` attributes carry the position and sha256 of every entry in the hash-chained ledger. Your SIEM can detect gaps or out-of-order writes without needing to ship the raw ledger file:

```sql
sir.ledger.index IS NOT NULL
| stats latest(sir.ledger.index) as max_idx,
        count_distinct(sir.ledger.hash) as unique_entries by sir.session.id
```

## Privacy guarantees

The following are enforced by code, not convention:

- `sir.target` is sha256-hashed before export whenever `sir.ifc.sensitivity = "secret"`. A clean allow-path `Read` of `~/.aws/credentials` never leaves the host as a plain string — it leaves as `sha256:<hex>`. The regression test for this lives in `TestPostEvaluate_AllowTraceMarksSensitiveTarget` in `pkg/hooks/evidence_test.go`.
- `sir.evidence` is redacted on the write path by the ledger store (`pkg/ledger/ledger_store.go`) and again on the emit path by `sanitizeLogEvent` in `pkg/telemetry/otlp_redact.go`, so a refactor that skips either layer still fails closed.
- Evidence redaction is mandatory, not configurable. The env-var gate controls only whether the field is populated at all.
- sir never emits cookies, session tokens, environment variable dumps, or provider API keys. The exporter has no access to process environment beyond its own configuration variables.

## Where to go next

- [docs/research/observability-design.md](../research/observability-design.md) explains where sir sits on Korman's three-tier model and why evidence logging is opt-in.
- [docs/user/runtime-security-overview.md](runtime-security-overview.md) is the operator-facing explanation of what sir catches at the boundary.
- [docs/user/faq.md](faq.md) has the short operator answer for "how do I query evidence in my SIEM".
