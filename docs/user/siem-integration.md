# SIEM Integration — OTLP Attribute Reference

> [!NOTE]
> sir is experimental — test on your own machine, not shared infrastructure. `sir doctor` recovers any wedged state; [report bugs](https://github.com/somoore/sir/issues).

sir emits every ledger entry to an operator-controlled SIEM collector via OTLP/HTTP JSON when the `SIR_OTLP_ENDPOINT` environment variable points at a reachable URL. The exporter uses only the Go standard library, never calls home, and redacts every attribute before serialization. This page documents the attribute names, the redaction rules, and how to write SIEM queries across the three observability tiers: governance, investigation, and detection.

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

sir uses the `sir.*` namespace so the attributes compose cleanly with OTLP resource attributes and with non-sir logs on the same collector. The session id is emitted as the resource attribute `sir.session_id`; everything else is a log-record attribute.

| Attribute                     | When present                               | Values / redaction                                                             |
|-------------------------------|--------------------------------------------|--------------------------------------------------------------------------------|
| `sir.session_id` (resource)   | every export                               | passthrough                                                                    |
| `sir.project_hash` (resource) | when a project root is known               | sha256 hex of the project path — never the raw path                            |
| `sir.tool_name`               | every entry                                | passthrough                                                                    |
| `sir.verb`                    | every entry                                | passthrough                                                                    |
| `sir.verdict`                 | every entry                                | `allow` / `deny` / `ask` / `alert`                                             |
| `sir.target`                  | when entry has a target                    | sha256 hash when `sir.ifc.sensitivity="secret"`, hostname-only for network verbs (`net_external`, `net_allowlisted`, `net_local`, `dns_lookup`, `push_origin`, `push_remote`) |
| `sir.reason`                  | every entry                                | `ledger.RedactString` removes known credential patterns                        |
| `sir.ifc.sensitivity`         | when IFC labeled                           | `secret` / `untrusted` / ...                                                   |
| `sir.ifc.trust`               | when IFC labeled                           | passthrough                                                                    |
| `sir.ifc.provenance`          | when IFC labeled                           | passthrough                                                                    |
| `sir.posture.state`           | every entry                                | passthrough                                                                    |
| `sir.posture.injection_alert` | when a pending injection alert exists      | boolean                                                                        |
| `sir.posture.mcp_taint`       | when any MCP server is tainted             | boolean                                                                        |
| `sir.session.secret`          | when the session holds secret-labeled data | boolean                                                                        |
| `sir.session.suspicion`       | when the session carries soft (non-blocking) risk | boolean — an untrusted read, an acknowledged-tainted MCP server, or elevated posture; promotes a detection's route one tier |
| `sir.ledger.index`            | every entry                                | monotonic integer                                                              |
| `sir.ledger.hash`             | every entry                                | sha256 hex, covers the full line                                               |
| `sir.lease.version`           | every entry                                | first 12 hex of the active lease hash — the authority-contract / policy version the SIEM can pivot on |
| `sir.decision_latency_ms`     | PreToolUse decisions                       | integer ms sir's decision added — dashboard p50/p95 for the "invisible latency" SLO |
| `sir.alert.type`              | alert entries                              | `credential_in_output` / `mcp_credential` / `mcp_injection` / `hook_tamper` / `sentinel_mutation` / `config_change_posture` / `posture_change` / `posture_change_session_end` / `elicitation_harvesting` |
| `sir.detection_id`            | entries that match a detection             | stable behavior-detection ID (see below): `secret_to_external_egress` / `secret_to_push_remote` / `mcp_injection_then_action` / `new_mcp_server_used` / `mcp_binary_or_config_drift` / `agent_posture_tamper` / `package_install_posture_mutation` / `repeated_denied_intent` / `credential_in_tool_output` / `control_plane_integrity_failure` / `mcp_change_then_privileged_use` |
| `sir.route`                   | entries that match a detection             | computed escalation route incl. dynamic promotion: `silent` / `local` / `siem` / `slack` |
| `sir.alert.severity`          | alert entries                              | `HIGH` / `MEDIUM` / `LOW`                                                      |
| `sir.alert.agent.id`          | hook-tamper entries                        | `claude` / `gemini` / `codex`                                                  |
| `sir.alert.diff_summary`      | posture alerts                             | `ledger.RedactString` applied                                                  |
| `sir.alert.restored`          | hook-tamper entries                        | boolean — whether auto-restore succeeded                                       |
| `sir.evidence`                | when `SIR_LOG_TOOL_CONTENT=1` is set       | credentials replaced with `[REDACTED:<class>]` markers; tool output evidence is truncated to 1024 bytes via `ledger.RedactContent`; MCP JSON arguments are redacted via `ledger.RedactMapValues`, JSON-marshaled, and truncated to 2048 bytes via `TruncateToWordBoundary` |

Note the difference between `sir.verb` and `sir.alert.type`. The verb is the sir policy classifier: for example, an MCP credential leak carries `sir.verb="mcp_credential_leak"` (from the policy surface) and `sir.alert.type="mcp_credential"` (from the alert taxonomy). Filter on the one you mean.

Evidence is redacted twice — once when the ledger store writes the line (`pkg/ledger/ledger_store.go`), and again in the telemetry exporter before emission (`pkg/telemetry/otlp_redact.go`) — so a future refactor that skips one path still cannot export raw credential content.

## Detection taxonomy and routing

`sir.detection_id` is a stable, causal classification of a decision — derived
from the verb, verdict, IFC sensitivity, and session/posture state, never from
raw command strings. It is distinct from `sir.alert.type`: the alert type is
the low-level signal taxonomy (e.g. `hook_tamper`), while the detection ID is
the behavior-level judgement (e.g. `agent_posture_tamper`, or
`control_plane_integrity_failure` when the tamper could not be auto-restored).
Filter on `sir.detection_id` for "what kind of behavior happened"; filter on
`sir.alert.type` for "which low-level check fired".

The ten detection IDs and where they are routed:

| Detection ID | Severity | Route |
|---|---|---|
| `secret_to_external_egress` | HIGH | SIEM (Slack if unusual/repeated) |
| `secret_to_push_remote` | HIGH | SIEM (Slack if unusual/repeated) |
| `mcp_injection_then_action` | HIGH | SIEM + Slack |
| `new_mcp_server_used` | MEDIUM | SIEM |
| `mcp_binary_or_config_drift` | HIGH | SIEM + Slack |
| `agent_posture_tamper` | HIGH | SIEM + Slack |
| `package_install_posture_mutation` | HIGH | SIEM + Slack |
| `repeated_denied_intent` | LOW | local (developer-facing) |
| `credential_in_tool_output` | HIGH | SIEM + Slack |
| `control_plane_integrity_failure` | HIGH | SIEM + Slack |
| `mcp_change_then_privileged_use` | HIGH | SIEM + Slack |

Every detection is written to the local ledger and, when `SIR_OTLP_ENDPOINT`
is set, to the SIEM. The actual escalation route for an event — including
dynamic promotion from suspicion or repetition — is emitted as `sir.route`
(`silent`/`local`/`siem`/`slack`).

Slack escalation is a separate opt-in with two modes:

- `SIR_SLACK_RELAY` (preferred): sir POSTs a structured JSON `SlackEvent` to a
  central, operator-run relay. The event carries the detection ID, severity,
  curated narrative, a `dedup_key`, and `suggested_actions` (label + exact `sir`
  command). The relay deduplicates across the fleet, routes by severity, renders
  the suggested actions as interactive buttons, and posts digests. Interactive
  buttons live in the relay because a workstation cannot host a Slack
  interaction endpoint. This keeps secrets and per-event spam off Slack and
  webhook URLs off individual machines. `sir relay` is the bundled reference
  implementation: run it on one host with the downstream `SIR_SLACK_WEBHOOK`
  set, point each workstation's `SIR_SLACK_RELAY` at
  `http://<relay-host>:8787/v1/detections`, and configure the Slack app's
  interactivity URL at `/slack/interactions`. It exposes `/healthz` and
  `/stats` (forwarded/suppressed/interaction counts), audit-logs every forward
  and button click, and accepts `--dedup` / `--digest` windows.

  Button clicks echo the exact remediation command back as an ephemeral
  message for the developer to run on the affected workstation; the relay never
  executes commands on a machine. That is deliberate: a relay that mutated
  fleet leases would be the central control plane sir's threat model is built
  to avoid. Central lease changes that must take effect on machines flow
  through the authenticated managed-policy channel (`SIR_MANAGED_POLICY_PATH`),
  not Slack.
- `SIR_SLACK_WEBHOOK`: the simple direct path for an individual developer — sir
  posts the plain `{"text":...}` curated message straight to a Slack webhook.

Either way, sir posts only for Slack-routed events and never includes raw
evidence. Repeated denies and routine secret-read/onboarding signals never
reach Slack, which keeps the channel actionable.

`sir friction` reads the same ledger to summarize prompts, blocks, repeated
prompts, the noisiest rules, the top blocked hosts and MCP servers, decision
latency (p50/p95, also emitted as `sir.decision_latency_ms`), and bypass
signals (unlocks and uninstalls), and reports each against a service-level
target with an OK/OVER status. Uninstall is recorded as a `sir_uninstall`
ledger marker and OTLP event before the hooks are removed, so bypassing sir is
observable rather than silent. `sir policy suggest` turns the same data into
narrowly-scoped lease recommendations.
Both read correctly after an observe-only rollout (`sir install --observe`),
where decisions are recorded as `would_allow` / `would_ask` / `would_deny`
with detection IDs but nothing blocks.

Policy profiles tune the friction/strictness tradeoff: `personal` (raw secret
reads prompt once, turn-scoped taint), `team` (raw secret reads are denied and
the agent uses the redacted `sir secret view` instead, so values never enter
the model context), and `strict` (team plus no delegation, no auto-lease, and a
minimal host allowlist). Choose one with `sir policy init --profile <name>`.

When `auto_lease_approved_hosts` is enabled (default for fresh installs, off in
the strict profile and in managed mode), sir turns an *observed* egress
approval into a 15-minute host lease automatically: a host that is asked at
PreToolUse and then actually executes — which only happens if the developer
approved it — is added to `approved_hosts` with a TTL, so the same host stops
prompting. The lease change is recorded as a `lease_modify` ledger entry and is
never minted from raw prompt counts, under secret/tainted posture, or in
managed mode. `sir policy show` reports the current setting.

## Example queries

sir ships three observability tiers. These snippets are written in generic pseudocode — translate the filter/group clauses into your collector's native syntax (SPL, LogScale query language, Datadog log query, KQL, etc).

### Tier 3 — detection (alerts in real time)

Find every alert entry in the last hour, grouped by alert type and tool:

```text
filter   sir.alert.type in ["credential_in_output", "mcp_credential", "mcp_injection", "hook_tamper"]
  and    @timestamp >= now - 1h
group by sir.alert.type, sir.tool_name
  count
```

### Tier 2 — investigation (reconstruct what happened)

Find every MCP credential leak where the redacted payload survived the exporter, so you can drill into what was about to be sent. Note the verb / alert-type split — the policy verb is `mcp_credential_leak`, the alert type is `mcp_credential`:

```text
filter sir.verb = "mcp_credential_leak"
  and  sir.evidence != ""
select @timestamp, sir.tool_name, sir.target, sir.evidence
```

sir writes a `tool_trace` ledger entry for every clean allow-path tool call when `SIR_LOG_TOOL_CONTENT=1`. That is the entry type to query when investigating "what did the agent actually read" after the fact:

```text
filter sir.verb = "tool_trace"
  and  sir.verdict = "allow"
  and  sir.session.secret = true
select @timestamp, sir.tool_name, sir.target, sir.evidence
```

### Governance — chain-of-custody

The `sir.ledger.index` and `sir.ledger.hash` attributes carry the position and sha256 of every entry in the hash-chained ledger. Your SIEM can detect gaps or out-of-order writes without needing to ship the raw ledger file. Group by the resource attribute `sir.session_id`, not a log attribute:

```text
filter   sir.ledger.hash != ""
group by sir.session_id
  max(sir.ledger.index)       as max_idx
  count_distinct(sir.ledger.hash) as unique_entries
```

## Privacy guarantees

The following are enforced by code, not convention:

- `sir.target` is sha256-hashed before export whenever `sir.ifc.sensitivity = "secret"`. A clean allow-path `Read` of `~/.aws/credentials` never leaves the host as a plain string — it leaves as `sha256:<hex>`. The regression test for this lives in `TestPostEvaluate_AllowTraceMarksSensitiveTarget` in `pkg/hooks/evidence_test.go`.
- `sir.evidence` is redacted on the write path by the ledger store (`pkg/ledger/ledger_store.go`) and again on the emit path by `sanitizeLogEvent` in `pkg/telemetry/otlp_redact.go`, so a refactor that skips either layer still fails closed.
- Evidence redaction is mandatory, not configurable. The env-var gate controls only whether the field is populated at all.
- sir never emits cookies, session tokens, environment variable dumps, or provider API keys. The exporter has no access to process environment beyond its own configuration variables.

## Where to go next

- [docs/research/observability-design.md](../research/observability-design.md) explains where sir sits on the three-tier observability model and why evidence logging is opt-in.
- [docs/user/runtime-security-overview.md](runtime-security-overview.md) is the operator-facing explanation of what sir catches at the boundary.
- [docs/user/faq.md](faq.md) has the short operator answer for "how do I query evidence in my SIEM".
- [docs/research/sir-threat-model.md](../research/sir-threat-model.md) covers the attacker model and the tradeoffs behind the attribute set.
