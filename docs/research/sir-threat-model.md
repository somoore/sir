# sir Threat Model

sir protects developers from things happening to them while using AI coding agents. It enforces lease-based authority boundaries through the hook systems exposed by Claude Code, Gemini CLI, and Codex, with defense in depth around posture tamper, credential handling, and investigation evidence.

sir is not a complete containment boundary. This document focuses on the shipped threat model, the trust assumptions behind it, and the residual risk that remains.

<!-- BEGIN GENERATED SUPPORT SCOPE -->
**Scope note.** The threat model is written primarily against Claude Code because Claude Code is the **reference-support** target: it has the richest hook surface (10 events), native interactive approval, and the most complete sir coverage. Gemini CLI has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but four Claude-specific lifecycle mitigations are not available: SubagentStart delegation gating, ConfigChange tamper detection at the moment of change, InstructionsLoaded pre-read scanning, and Elicitation interception. Codex has **limited support** with a Bash-only hook surface: Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools bypass PreToolUse, so sir relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [../user/codex-support.md](../user/codex-support.md) and [../user/gemini-support.md](../user/gemini-support.md) for the per-agent coverage matrices.
<!-- END GENERATED SUPPORT SCOPE -->

## Assets and trust boundaries

The assets sir is trying to protect are straightforward:

- credentials and other sensitive local files
- the host agent's hook config
- project posture files such as `CLAUDE.md` and `.mcp.json`
- the active lease and session state
- the integrity of the forensic ledger

The core trust boundaries are:

- tool calls crossing from the model into the local machine
- hook-managed policy decisions between Go and Rust
- external sinks such as network egress, pushes, and untrusted MCP servers
- the sir-owned canonical state under `~/.sir/`

## Adversary model

sir assumes an attacker can:

- inject instructions through repository content, MCP responses, or fetched content
- publish malicious packages with postinstall tamper
- influence the agent into reading, writing, or exfiltrating data the developer did not intend

sir does not assume the attacker can:

- modify sir binaries directly
- gain kernel-level control of the host
- bypass the host agent and write arbitrary state under `~/.sir/`

## In-scope threats

### Confused deputy actions

Threat: the agent is induced to take actions the developer did not intend.

Mitigations:

- sensitive reads are approval-gated
- posture-file writes are approval-gated
- risky sinks are checked against trust and session posture
- every decision is logged to the ledger

### Credential exfiltration

Threat: the agent reads `.env`, `*.pem`, `.aws/*`, or similar data and tries to send it outward.

Mitigations:

- the read is asked before execution
- approval marks the turn or session as secret
- secret posture blocks untrusted egress and unapproved pushes
- `sir unlock` and explicit allowlists are visible, logged escape hatches

Residual risk: sir does not follow secrets through model reasoning, paraphrase, or arbitrary child processes.

### Supply-chain posture tamper

Threat: a package install modifies hook config, posture files, or other sir-critical state.

Mitigations:

- install sentinels are hashed before and after package installs
- posture drift triggers alerts and restore
- `sir doctor` can verify and repair from canonical state

Residual risk: sir catches filesystem consequences, not every runtime behavior of a malicious installer.

### MCP injection and credential leakage

Threat: remote content enters the model through MCP and steers the next action toward exfiltration or posture tamper.

Mitigations:

- MCP response scanning for common injection markers
- MCP argument scanning for credential disclosure
- elevated posture after injection signals
- optional `sir mcp` and `sir mcp wrap` hardening for command-based servers

Residual risk: encoded or non-English prompt-injection techniques that avoid the known literal patterns are not guaranteed to be caught at `PostToolUse`.

The fail-closed backstop is downstream: credential detection can still mark the session secret, and secret-session IFC plus delegation gating still apply on the next tool use even when the original MCP framing was opaque to the literal scanner.

### Posture disablement

Threat: the agent edits hook config or other posture files to remove sir from the loop.

Mitigations:

- writes to posture files are gated
- the sir-owned hook subtree is hashed and restored from canonical state
- serious drift triggers deny-all until verified

## Managed mode and runtime containment

Managed mode shifts the trust anchor from the local working copy to an org-owned manifest referenced by `SIR_MANAGED_POLICY_PATH`. In managed mode, `sir install` seeds state from that manifest and `sir doctor` restores managed lease and hook state instead of accepting new local baselines.

`sir run <agent>` is the optional below-hook layer:

- macOS uses localhost-only `sandbox-exec` plus a provider-aware local proxy with launch-time DNS pinning
- Linux uses `unshare --net` containment with exact-destination egress allowlisting and durable-state protection

Both are meaningful hardening layers, but still experimental.

## Privacy contract

The optional OTLP exporter is off unless `SIR_OTLP_ENDPOINT` is set. When enabled, it exports verdict metadata to infrastructure you already operate. Secret-labeled file paths are hashed before emission. If `SIR_LOG_TOOL_CONTENT=1` is also enabled, sir may attach redacted investigation evidence, not raw secrets.

## What remains out of scope

- model-internal reasoning and semantic laundering of secrets
- unrecognized child-process behavior below the shell classifier
- complete host containment on every platform
- same-user OS-level protection without help from the host agent or operating system

## Verification path

Use these before trusting a release or rollout:

- [validation-summary.md](validation-summary.md)
- [security-verification-guide.md](security-verification-guide.md)
- `go test ./...`
- `cargo test --locked`
- `make public-contract`
