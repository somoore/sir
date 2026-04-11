# sir Threat Model

> [!WARNING]
> **sir is experimental, in active development, and not yet suitable for production deployments.** No promises or guarantees are made at this stage. Test on your own machine, not shared infrastructure. If something goes wrong, run `sir doctor` to recover or `sir uninstall` to remove hooks cleanly. Report bugs via [GitHub issues](https://github.com/somoore/sir/issues) — contributions welcome.

sir ("Sandbox in Reverse") is an experimental security runtime for AI coding agents. Traditional sandboxes constrain a process from below — syscalls, filesystem jails, seccomp. sir inverts that: it constrains the *agent* from above, intercepting tool calls at the hook layer before they execute and routing them through a Rust policy oracle (`mister-core`) that returns allow, ask, or deny. Every decision is appended to an immutable hash-chained ledger.

This approach exists because AI coding agents are not a single sandboxable process. They orchestrate tools, spawn subprocesses, and call MCP servers. The dangerous surface is not syscalls — it is *intents* like "read `.env`, then `curl` an external host." sir uses **information flow control (IFC)** to track data sensitivity across operations: if the agent reads a secret file, that taint propagates to any file it writes, any commit, and any push attempt in the same session.

> **Warning:** sir is experimental and v1 has known limitations. It is not a complete containment boundary, the hook layer is advisory policy enforcement rather than OS-level prevention (unless `sir run` is used), and several detections are heuristic.

This document lays out the shipped threat model, the trust assumptions behind it, and the residual risk that remains so external researchers can evaluate it honestly.

<!-- BEGIN GENERATED SUPPORT SCOPE -->
**Scope note.** The threat model is written primarily against Claude Code because Claude Code is the **reference-support** target: it has the richest hook surface (10 events), native interactive approval, and the most complete sir coverage. Gemini CLI has **near-parity support** — full tool-path coverage for file IFC labeling, shell classification, MCP scanning, and credential output scanning — but four Claude-specific lifecycle mitigations are not available: SubagentStart delegation gating, ConfigChange tamper detection at the moment of change, InstructionsLoaded pre-read scanning, and Elicitation interception. Codex has **limited support** with a Bash-only hook surface: Bash-mediated sensitive reads are pre-gated, but native file writes and MCP tools bypass PreToolUse, so sir relies on sentinel hashing plus a final `Stop` sweep as the posture backstop. Wherever a mitigation below depends on one of the missing hooks, the threat is correspondingly wider on the affected agent. See [../user/codex-support.md](../user/codex-support.md) and [../user/gemini-support.md](../user/gemini-support.md) for the per-agent coverage matrices.
<!-- END GENERATED SUPPORT SCOPE -->

## Assets and trust boundaries

The assets sir is trying to protect are straightforward:

- Credentials and other sensitive local files.
- The host agent's hook config.
- Project posture files such as `CLAUDE.md` and `.mcp.json`.
- The active lease and session state.
- The integrity of the forensic ledger.

The core trust boundaries are:

- Tool calls crossing from the model into the local machine.
- Hook-managed policy decisions between Go and Rust.
- External sinks such as network egress, pushes, and untrusted MCP servers.
- The sir-owned canonical state under `~/.sir/`.

## Adversary model

sir assumes an attacker **can**:

- Inject instructions through repository content, MCP responses, or fetched content.
- Publish malicious packages with postinstall tamper.
- Influence the agent into reading, writing, or exfiltrating data the developer did not intend.

sir does **not** assume the attacker can:

- Modify sir binaries directly.
- Gain kernel-level control of the host.
- Bypass the host agent and write arbitrary state under `~/.sir/`.

## In-scope threats

### Confused deputy actions

**Threat:** the agent is induced to take actions the developer did not intend.

**Mitigations:**

- Sensitive reads are approval-gated.
- Posture-file writes are approval-gated.
- Risky sinks are checked against trust and session posture.
- Every decision is logged to the ledger.

### Credential exfiltration

**Threat:** the agent reads `.env`, `*.pem`, `.aws/*`, or similar data and tries to send it outward.

**Mitigations:**

- The read is asked before execution.
- Approval marks the turn or session as secret.
- Secret posture blocks untrusted egress and unapproved pushes.
- `sir unlock` and explicit allowlists are visible, logged escape hatches.

**Residual risk:** sir does not follow secrets through model reasoning, paraphrase, or arbitrary child processes.

### Supply-chain posture tamper

**Threat:** a package install modifies hook config, posture files, or other sir-critical state.

**Mitigations:**

- Install sentinels are hashed before and after package installs.
- Posture drift triggers alerts and restore.
- `sir doctor` can verify and repair from canonical state.

**Residual risk:** sir catches filesystem consequences, not every runtime behavior of a malicious installer.

### MCP injection and credential leakage

**Threat:** remote content enters the model through MCP and steers the next action toward exfiltration or posture tamper.

**Mitigations:**

- MCP response scanning for common injection markers.
- MCP argument scanning for credential disclosure.
- Elevated posture after injection signals.
- Optional `sir mcp` and `sir mcp wrap` hardening for command-based servers.

**Residual risk:** MCP injection detection is **heuristic** — roughly 50 regex patterns covering authority framing, exfil instructions, credential harvesting, and hidden markers. Encoded, paraphrased, or non-English prompt-injection techniques that avoid the literal patterns are not guaranteed to be caught at `PostToolUse`. This is a known v1 limitation.

The fail-closed backstop is downstream, and it is the load-bearing piece of this mitigation: credential detection can still mark the session secret, and secret-session IFC plus delegation gating still apply on the next tool use even when the original MCP framing was opaque to the literal scanner. Untrusted MCP servers are also tainted on detection, so future traffic is treated with elevated posture.

### Posture disablement

**Threat:** the agent edits hook config or other posture files to remove sir from the loop.

**Mitigations:**

- Writes to posture files are gated.
- The sir-owned hook subtree is hashed and restored from canonical state.
- Serious drift triggers deny-all until verified.

## Managed mode and runtime containment

Managed mode shifts the trust anchor from the local working copy to an org-owned manifest referenced by `SIR_MANAGED_POLICY_PATH`. In managed mode, `sir install` seeds state from that manifest and `sir doctor` restores managed lease and hook state instead of accepting new local baselines.

`sir run <agent>` is the optional below-hook layer:

- **macOS** uses localhost-only `sandbox-exec` plus a provider-aware local proxy with launch-time DNS pinning.
- **Linux** uses `unshare --net` containment with exact-destination egress allowlisting and durable-state protection.

Both are meaningful hardening layers and are the only parts of sir that provide OS-level prevention rather than hook-layer policy. They remain experimental and are not yet a cross-platform transparent egress firewall.

## Privacy contract

The optional OTLP exporter is off unless `SIR_OTLP_ENDPOINT` is set. When enabled, it exports verdict metadata to infrastructure you already operate. Secret-labeled file paths are hashed before emission. If `SIR_LOG_TOOL_CONTENT=1` is also enabled, sir may attach redacted investigation evidence, not raw secrets.

## What remains out of scope

Being explicit about what sir does not cover matters more than claiming broad protection. The following are outside the v1 threat model:

- **Model-internal reasoning and semantic laundering of secrets** — sir cannot follow a secret through the model's paraphrase or summarization.
- **Unrecognized child-process behavior below the shell classifier** — the shell classifier is lexical and can be evaded by novel wrappers.
- **Complete host containment on every platform** — `sir run` is macOS and Linux only, and still experimental.
- **Same-user OS-level protection** without help from the host agent or operating system.
- **Turn-boundary precision** — sir uses a 30-second gap heuristic to approximate turn boundaries, which can be wrong under unusual pacing.
- **The default lease**, which is deliberately permissive to reduce developer friction and is not a hardened profile.

> **Note:** If you find a way to violate one of the in-scope guarantees above, that is a security bug and we want to hear about it. See the verification path below.

## Verification path

If you are a researcher evaluating sir, start here. These are the fastest paths to form your own opinion before trusting a release or rollout, and to reproduce the claims above:

- [validation-summary.md](validation-summary.md) — the short evidence view.
- [security-verification-guide.md](security-verification-guide.md) — runnable end-to-end checks against a fresh install.
- `go test ./...` — full Go test surface including IFC, hooks, ledger, and MCP scanning.
- `cargo test --locked` — `mister-core` policy oracle and shared protocol.
- `make public-contract` — keeps shipped docs and toolchain promises aligned with the code.

To contribute findings, file a bug report for false negatives or classifier gaps, and follow the security vulnerability process for anything that crosses an in-scope guarantee. We would rather hear about a credible bypass than ship around one.
